import dns

def test_parse_query():
    query = read_file('query.txt')
    packet = dns.parse_dns_packet(query)
    assert(packet.questions[0].domain == [b'ca'])

def test_parse_response():
    query = read_file('response.txt')
    packet = dns.parse_dns_packet(query)
    assert(len(packet.authorities) == 13)
    expected = dns.ResponseRecord(record_type=2, cls=1, ttl=518400, rdlength=4, data=b'\x01d\xc0!')
    assert(packet.authorities[12] == expected)
    assert(packet.additionals == [dns.ResponseRecord(record_type=41, cls=4096, ttl=0, rdlength=0, data=b'')])

def test_parse_recursive_response():
    expected_response = read_file('recursive_response.txt')
    packet = dns.parse_dns_packet(expected_response)
    response = dns.create_response(packet.msg_id, packet.questions[0].domain, packet.answers[0].data, packet.answers[0].ttl)
    print(expected_response)
    print(response)
    assert(False)


def test_create_query():
    expected_query = read_file('query.txt')
    packet = dns.parse_dns_packet(expected_query)
    query = dns.create_dns_query(packet.msg_id, [b'ca'])
    mismatches = [(x,y) for x,y in zip(query, expected_query) if x != y]
    assert(len(mismatches) == 1)


def read_file(filename):
    with open(filename) as f:
        return bytes.fromhex(f.read().strip())
