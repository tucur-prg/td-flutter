import 'dart:io';
import 'dart:typed_data';
import 'dart:convert';

void main() async {
  final query = buildDnssecQuery('example.com');

  final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
  socket.send(query, InternetAddress('8.8.8.8'), 53);

  print("request (${query.length} bytes)");
  dumpRequest(query);

  socket.listen((event) {
    if (event == RawSocketEvent.read) {
      final datagram = socket.receive();
      if (datagram != null) {
        print('response (${datagram.data.length} bytes)');
        dumpResponse(datagram.data);
        socket.close();
      }
    }
  });
}

/// DNSSEC対応クエリ構築
Uint8List buildDnssecQuery(String domain) {
  final buffer = BytesBuilder();

  // トランザクションID (適当な2バイト)
  buffer.add([0x12, 0x34]);

  // Flags: 標準クエリ + Recursion Desired (0x0100)
  buffer.add([0x01, 0x00]);

  // Questions: 1
  buffer.add([0x00, 0x01]);

  // Answer RRs: 0
  buffer.add([0x00, 0x00]);

  // Authority RRs: 0
  buffer.add([0x00, 0x00]);

  // Additional RRs: 1 （OPTレコード）
  buffer.add([0x00, 0x01]);

  // QNAME
  for (var part in domain.split('.')) {
    buffer.addByte(part.length);
    buffer.add(utf8.encode(part));
  }
  buffer.addByte(0x00);

  // QTYPE: A (0x0001)
//  buffer.add([0x00, 0x01]);
  // QTYPE: DNSKEY (0x0030)
  buffer.add([0x00, 0x30]);

  // QCLASS: IN (0x0001)
  buffer.add([0x00, 0x01]);

  // --- OPT Record (EDNS0) ---

  // NAME: 0 (root)
  buffer.addByte(0x00);

  // TYPE: OPT (41)
  buffer.add([0x00, 0x29]);

  // UDP payload size: 4096 bytes (0x1000)
  buffer.add([0x10, 0x00]);

  // EXTENDED RCODE and flags: DO bit set (DNSSEC OK)
  // Upper 8 bits RCODE = 0, flags = 0x8000 (DO bit is highest bit of flags)
  buffer.add([0x00, 0x00]); // extended RCODE, version
  buffer.add([0x80, 0x00]); // flags with DO bit set

  // RDLEN: 0 (no data)
  buffer.add([0x00, 0x00]);

  return buffer.toBytes();
}

void dumpRequest(Uint8List request) {
  print("\n---- Request DUMP ----\n");

  print("> header");
  print("ID: ${convert(request.sublist(0, 2))}");

  print("QR: ${bits(request[2], 8, 1)}");
  print("Opcode: ${bits(request[2], 4, 4)}");
  print("AA: ${bits(request[2], 3, 1)}");
  print("TC: ${bits(request[2], 2, 1)}");
  print("RD: ${bits(request[2], 1, 1)}");

  print("RA: ${bits(request[3], 8, 1)}");
  print("Z: ${bits(request[3], 7, 1)}");
  print("AD: ${bits(request[3], 6, 1)}");
  print("CD: ${bits(request[3], 5, 1)}");
  print("RCode: ${bits(request[3], 1, 4)}");

  var qd = request[4] << 8 | request[5];
  print("QDCOUNT: $qd");
  var an = request[6] << 8 | request[7];
  print("ANCOUNT: $an");
  var ns = request[8] << 8 | request[9];
  print("NSCOUNT: $ns");
  var ar = request[10] << 8 | request[11];
  print("ARCOUNT: $ar");
  print("");

  print("> body");

  var seq = 12;
  print(">>> Question Section");
  for (var i = 0; i < qd; i++) {
    List<String> name = List.empty(growable: true);
    while (request[seq] != 0) {
      int len = request[seq];
      seq++;
      name.add(String.fromCharCodes(request.sublist(seq, seq + len)));
      seq += len;
    }
    seq++;

    final qtype = request.sublist(seq, seq + 2);
    final qclass = request.sublist(seq + 2, seq + 4);
    seq += 4;
    print("${name.join('.')} $qtype $qclass");
  }
  print("");

  print(">>> Answer Section");
  print("");

  print(">>> Authority Section");
  print("");

  print(">>> Additional Section");
  for (var i = 0; i < ar; i++) {
    // XXX: EDNS の場合の構造
    var name = request.sublist(seq, seq + 2);
    var type = request.sublist(seq + 2, seq + 3);
    var clz = request.sublist(seq + 3, seq + 5);
    var ttl = request.sublist(seq + 5, seq + 8);
    var len = request[seq + 8] << 8 | request[seq + 9];
    var data = request.sublist(seq + 9, seq + 9 + len);

    print("$name $type $clz $ttl $len $data");
    seq += 12 + len;
  }
  print("");
}

void dumpResponse(Uint8List response) {
  print("\n---- Response DUMP ----\n");
//  print(response.sublist(0, 12));
  print("> header");
  print("ID: ${convert(response.sublist(0, 2))}");

  print("QR: ${bits(response[2], 8, 1)}");
  print("Opcode: ${bits(response[2], 4, 4)}");
  print("AA: ${bits(response[2], 3, 1)}");
  print("TC: ${bits(response[2], 2, 1)}");
  print("RD: ${bits(response[2], 1, 1)}");

  print("RA: ${bits(response[3], 8, 1)}");
  print("Z: ${bits(response[3], 7, 1)}");
  print("AD: ${bits(response[3], 6, 1)}");
  print("CD: ${bits(response[3], 5, 1)}");
  print("RCode: ${bits(response[3], 1, 4)}");

  var qd = response[4] << 8 | response[5];
  print("QDCOUNT: $qd");
  var an = response[6] << 8 | response[7];
  print("ANCOUNT: $an");
  var ns = response[8] << 8 | response[9];
  print("NSCOUNT: $ns");
  var ar = response[10] << 8 | response[11];
  print("ARCOUNT: $ar");
  print("");

  print("> body");
//  print(response.sublist(12));

  var seq = 12;
  print(">>> Question Section");
  for (var i = 0; i < qd; i++) {
    List<String> name = List.empty(growable: true);
    while (response[seq] != 0) {
      int len = response[seq];
      seq++;
      name.add(String.fromCharCodes(response.sublist(seq, seq + len)));
      seq += len;
    }
    seq++;

    final qtype = response.sublist(seq, seq + 2);
    final qclass = response.sublist(seq + 2, seq + 4);
    seq += 4;
    print("${name.join('.')} $qtype $qclass");
  }
  print("");

  print(">>> Answer Section");
//  print(response.sublist(seq));
  for (var i = 0; i < an; i++) {
    var name = response.sublist(seq, seq + 2);
    var compress = (name[0] & 0xC0) == 0xC0;
    var type = response.sublist(seq + 2, seq + 4);
    var clz = response.sublist(seq + 4, seq + 6);
    var ttl = response.sublist(seq + 6, seq + 10);
    var len = response[seq + 10] << 8 | response[seq + 11];
    var data = response.sublist(seq + 12, seq + 12 + len);

    print("$compress $name $type $clz $ttl $len $data");
    seq += 12 + len;
  }
  print("");

  print(">>> Authority Section");
  for (var i = 0; i < ns; i++) {
    // XXX: あとで
  }
  print("");

  print(">>> Additional Section");
//  print(response.sublist(seq));
  for (var i = 0; i < ar; i++) {
    // XXX: EDNS の場合の構造
    var name = response.sublist(seq, seq + 2);
    var type = response.sublist(seq + 2, seq + 3);
    var clz = response.sublist(seq + 3, seq + 5);
    var ttl = response.sublist(seq + 5, seq + 8);
    var len = response[seq + 8] << 8 | response[seq + 9];
    var data = response.sublist(seq + 9, seq + 9 + len);

    print("$name $type $clz $ttl $len $data");
    seq += 12 + len;
  }
}

int bits(int byte, int index, int length) {
  return (byte >> (index - 1)) & ((1 << length) - 1);
}

List<String> convert(List<int> data) {
  return data.map((n) => "0x" + n.toRadixString(16).padLeft(2, '0')).toList();
}
