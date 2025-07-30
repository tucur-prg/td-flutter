import 'dart:io';

Future<void> main() async {
  final host = 'example.com';
  final port = 443;

  // ① 自前のDNS解決処理（例: DNSSEC、DoHなど）
  final ipList = await mySecureDnsLookup(host);

  if (ipList.isEmpty) {
    throw Exception('Failed to resolve host: $host');
  }

  // ② IPでソケット接続
  final rawSocket = await Socket.connect(ipList.first, port);

  // ③ SecureSocketに昇格（host名SNIはここで渡す）
  final secureSocket = await SecureSocket.secure(
    rawSocket,
    host: host, // SNIと証明書検証のため必要
    //    onBadCertificate: (cert) => true,
  );

  // 通信処理など
  secureSocket
      .writeln('GET / HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n');
  secureSocket.listen((data) {
    print(String.fromCharCodes(data));
  });

  secureSocket.close();
}

Future<List<InternetAddress>> mySecureDnsLookup(String host) async {
  // ここに自前のDNSSECやDoHなどの処理を書く
  return [InternetAddress('23.192.228.84')];
}
