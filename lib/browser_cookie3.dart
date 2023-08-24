library browser_cookie3;

import 'dart:async';
import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:io';

import 'package:cryptography/cryptography.dart';
import 'package:path/path.dart' as p;
import 'package:sqlite3/sqlite3.dart';

typedef _ConnectionMethod = Future<Database?> Function();

class _DatabaseConnection {
  static bool _checkConnectionOk(Database database) {
    try {
      database.execute('select 1 from sqlite_master');
      return true;
    } catch (e) {
      return false;
    }
  }

  final File _databaseFile;

  String? _tempCookieFile;
  Database? _database;
  late List<_ConnectionMethod> _methods;

  _DatabaseConnection({
    required File databaseFile,
    bool tryLegacyFirst = false,
  }) : _databaseFile = databaseFile {
    _methods = [_sqlite3ConnectReadonly];
    if (tryLegacyFirst) {
      _methods.insert(0, _getConnectionLegacy);
    } else {
      _methods.add(_getConnectionLegacy);
    }
  }

  Future<Database?> _sqlite3ConnectReadonly() async {
    const List<String> options = [
      '?mode=ro',
      '?mode=ro&nolock=1',
      '?mode=ro&immutable=1',
    ];
    final Uri uri = _databaseFile.absolute.uri;
    for (String option in options) {
      final Database database;
      try {
        database = sqlite3.open('$uri$option', uri: true);
      } catch (e) {
        continue;
      }
      if (_checkConnectionOk(database)) {
        return database;
      }
    }
    return null;
  }

  Future<Database?> _getConnectionLegacy() async {
    final Directory tempDir = await Directory.systemTemp.createTemp();
    final File tempFile = File(p.join(tempDir.path, 'temptemp.sqlite'));
    await _databaseFile.copy(tempFile.path);
    _tempCookieFile = tempFile.path;

    final Database database = sqlite3.open(tempFile.path);
    if (_checkConnectionOk(database)) return database;
    return null;
  }

  Future<Database> loadDatabase() async {
    final Database? currentDatabase = _database;
    if (currentDatabase != null) {
      return currentDatabase;
    }
    for (_ConnectionMethod method in _methods) {
      final Database? database = await method();
      if (database == null) continue;
      _database = database;
      return database;
    }
    throw StateError('Unable to read database file');
  }

  Future<T> use<T>(FutureOr<T> Function(Database) usage) async {
    final Database database = await loadDatabase();
    final T result = await usage(database);
    await dispose();
    return result;
  }

  Future<void> dispose() async {
    _database?.dispose();
    final String? tempCookieFile = _tempCookieFile;
    if (tempCookieFile != null) {
      await File(tempCookieFile).delete(recursive: true);
    }
  }
}

class Location {
  final String env;
  final String path;

  const Location({required this.env, required this.path});

  File get file {
    return File(p.normalize(p.join(Platform.environment[env] ?? '', path)));
  }
}

final class DataBlob extends ffi.Struct {
  @ffi.Long()
  external int cbData;

  external ffi.Pointer<ffi.Char> pbData;
}

class ChromiumBased {
  static const int unixToNtEpochOffset = 11644473600;

  final String browser;
  final String domainName;
  final List<int> _salt;
  final List<int> _iv;
  final int _length;

  List<int>? _v10Key;

  late Future<File?> _cookieFileFuture;

  ChromiumBased({
    required this.browser,
    this.domainName = '',
    File? cookieFile,
    File? keyFile,
    List<Location> cookiesLocations = const [],
    List<Location> keysLocations = const [],
  })  : _salt = [115, 97, 108, 116, 121, 115, 97, 108, 116] /* b"saltysalt" */,
        _iv = List.filled(16, 32 /* ASCII space */),
        _length = 16 {
    _cookieFileFuture = _addKeyAndCookieFile(
      cookieFile: cookieFile,
      keyFile: keyFile,
      cookiesLocations: cookiesLocations,
      keysLocations: keysLocations,
    );
  }

  Future<File?> _addKeyAndCookieFile({
    File? cookieFile,
    File? keyFile,
    List<Location> cookiesLocations = const [],
    List<Location> keysLocations = const [],
  }) async {
    keyFile ??= _expandPaths(keysLocations);
    if (keyFile != null) {
      final Map keyFileJson = jsonDecode(await keyFile.readAsString());
      final String key64 = keyFileJson['os_crypt']['encrypted_key'];

      // Decode Key, get rid of DPAPI prefix, unprotect data
      final List<int> keyDpApi = base64Decode(key64).sublist(5);
      _v10Key = _cryptUnprotectedData(cypherText: keyDpApi, isKey: true).$2;
    } else {
      _v10Key = null;
    }

    // TODO Implement to Chrome
    return cookieFile ?? _expandPaths(cookiesLocations);
  }

  @override
  String toString() => browser;

  Future<List<Cookie>> loadCookies() async {
    final File? cookieFile = await _cookieFileFuture;
    if (cookieFile == null) {
      throw StateError('Failed to find $browser cookie');
    }
    final List<Cookie> cookies = [];
    await _DatabaseConnection(databaseFile: cookieFile).use((cursor) async {
      late final ResultSet items;
      try {
        // Chrome < 56
        items = cursor.select(
          'SELECT host_key, path, secure, expires_utc, name, value, encrypted_value, is_httponly '
          'FROM cookies WHERE host_key like ?;',
          ['%$domainName%'],
        );
      } catch (e) {
        // Chrome >= 56
        items = cursor.select(
          'SELECT host_key, path, is_secure, expires_utc, name, value, encrypted_value, is_httponly '
          'FROM cookies WHERE host_key like ?;',
          ['%$domainName%'],
        );
      }
      for (Row item in items) {
        final String host = item[0];
        final String path = item[1];
        final bool secure = item[2];
        final num expiresNtTimeEpoch = item[3];
        final String name = item[4];
        String value = item[5];
        final List<int> encValue = item[6];
        final bool httpOnly = item[7];

        final int? expires;
        if (expiresNtTimeEpoch == 0) {
          expires = null;
        } else {
          expires = (expiresNtTimeEpoch ~/ 1000000) - unixToNtEpochOffset;
        }
        value = await _decrypt(value, encValue);
        cookies.add(_createCookie(
          host: host,
          path: path,
          secure: secure,
          expires: expires,
          name: name,
          value: value,
          httpOnly: httpOnly,
        ));
      }
    });
    return cookies;
  }

  static List<Location> _generateWinPathsChromium(List<String> paths) {
    return paths.expand((path) {
      // TODO 'Profile *' e 'Edge*'
      return [
        Location(env: 'APPDATA', path: '..\\Local\\$path'),
        Location(env: 'LOCALAPPDATA', path: path),
        Location(env: 'APPDATA', path: path),
      ];
    }).toList();
  }

  static Iterable<File> _expandPathsImpl(List<Location> locations) sync* {
    for (Location location in locations) {
      final File file = location.file;
      if (file.existsSync()) {
        yield file;
      }
    }
  }

  static File? _expandPaths(List<Location> locations) {
    return _expandPathsImpl(locations).firstOrNull;
  }

  static Cookie _createCookie({
    required String host,
    required String path,
    required bool secure,
    required int? expires,
    required String name,
    required String value,
    required bool httpOnly,
  }) {
    return Cookie(name, value)
      ..domain = host
      ..path = path
      ..secure = secure
      ..expires =
          expires == null ? null : DateTime.fromMillisecondsSinceEpoch(expires)
      // TODO Check if use fromMillisecondsSinceEpoch or fromMicrosecondsSinceEpoch
      ..httpOnly = httpOnly;
  }

  static String _decryptWindowsChromium(
    String value,
    List<int> encryptedValue,
  ) {
    if (value.isEmpty) return value;
    if (encryptedValue.isEmpty) return '';
    return utf8.decode(_cryptUnprotectedData(cypherText: encryptedValue).$2);
  }

  Future<String> _decrypt(String value, List<int> encryptedValue) async {
    try {
      return _decryptWindowsChromium(value, encryptedValue);
    } catch (e) {
      final List<int>? v10Key = _v10Key;
      if (v10Key == null) {
        throw StateError(
          'Failed to decrypt the cipher text with DPAPI and no AES key.',
        );
      }
      encryptedValue = encryptedValue.sublist(3);
      final List<int> nonce = encryptedValue.take(12).toList();
      final List<int> tag = encryptedValue.sublist(encryptedValue.length - 16);

      // TODO Check if correct
      final AesGcm algorithm = AesGcm.with128bits();
      final List<int> data;
      try {
        data = await algorithm.decrypt(
          SecretBox(
            encryptedValue.sublist(12, encryptedValue.length - 16),
            nonce: nonce,
            mac: Mac(tag), // TODO Check how to correlate
          ),
          secretKey: SecretKey(tag), // TODO Check how to correlate
        );
      } catch (e) {
        throw StateError('Unable to get key for cookie decryption');
      }
      return utf8.decode(data);
    }
  }

  static (String, List<int>) _cryptUnprotectedData({
    List<int> cypherText = const [],
    List<int> entropy = const [],
    Object? reserved,
    Object? promptStruct,
    bool isKey = false,
  }) {
    // TODO: Implement
    throw UnimplementedError();
    // final ffi.Pointer<DataBlob> blobIn = calloc<DataBlob>();
    // blobIn.ref.cbData = cypherText.length;
    //
    // final ffi.Pointer<DataBlob> blobEntropy = calloc<DataBlob>();
    // blobIn.ref.cbData = entropy.length;
    //
    // final ffi.Pointer<DataBlob> blobOut = calloc<DataBlob>();
    // blobIn.ref.cbData = 0;
    //
    // const int cryptProtectUiForbidden = 0x01;
    //
    // calloc.free(blobIn);
    // calloc.free(blobEntropy);
    // calloc.free(blobOut);
  }
}

void main() async {
  final ChromiumBased edge = ChromiumBased(
    browser: 'Edge',
    cookiesLocations: ChromiumBased._generateWinPathsChromium(
      [
        p.join(
          'Microsoft',
          'Edge',
          'User Data',
          'Default',
          'Cookies',
        ),
        p.join(
          'Microsoft',
          'Edge',
          'User Data',
          'Default',
          'Network',
          'Cookies',
        ),
        p.join(
          'Microsoft',
          'Edge',
          'User Data',
          'Profile 1',
          'Cookies',
        ),
        p.join(
          'Microsoft',
          'Edge',
          'User Data',
          'Profile 1',
          'Network',
          'Cookies',
        ),
      ],
    ),
    keysLocations: ChromiumBased._generateWinPathsChromium(
      [p.join('Microsoft', 'Edge', 'User Data', 'Local State')],
    ),
  );
  print(await edge.loadCookies());
}
