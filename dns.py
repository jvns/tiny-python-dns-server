import socket
import struct
import random
from collections import namedtuple

ResponseRecord = namedtuple('ResponseRecord', 'record_type cls ttl rdlength data')
Question = namedtuple('Question', 'domain record_type cls')
DNS = namedtuple('DNS', 'msg_id flags questions answers authorities additionals')

def run():
    s = udp_socket()
    s.bind(('0.0.0.0', 6363))
    while True:
        query_packet, addr = s.recvfrom(65000)
        response = reply(query_packet)
        s.sendto(response, addr)

def reply(query_packet):
    packet = parse_dns_packet(query_packet)
    domain = packet.questions[0].domain
    ip, ttl = recurse(domain)
    response = create_response(packet.msg_id, domain, ip, ttl)
    return response

def udp_socket():
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def parse_dns_packet(packet):
    msg_id, flags, question_count, answer_count, authority_count, additional_count = struct.unpack('!HHHHHH', packet[:12])
    # we only handle questions
    questions = []
    rest = packet[12:]
    questions, rest = process(question_count, rest, parse_question)
    answers, rest = process(answer_count, rest, parse_resource_record)
    authorities, rest = process(authority_count, rest, parse_resource_record)
    additionals, rest = process(additional_count, rest, parse_resource_record)
    assert(len(rest) == 0)
    return DNS(msg_id, flags, questions, answers, authorities, additionals)

def process(count, rest, function):
    # dumb metaprogramming nonsense
    things = []
    for _ in range(count):
        thing, rest = function(rest)
        things.append(thing)
    return things, rest

def parse_question(rest):
    parts, rest = get_domain(rest)
    record_type, cls = struct.unpack("!HH", rest[0:4])
    rest = rest[4:]
    return Question(parts, record_type, cls), rest

def get_domain(rest):
    if rest[0] & 0b11000000 == 192:
        # it's a pointer, see "message compression" section
        # todo: actually dereference the pointer
        return "uh it's a pointer??", rest[2:]
    parts = []
    while rest[0] != 0:
        domain_length = struct.unpack("!B", rest[0:1])[0]
        domain = rest[1:domain_length+1]
        parts.append(domain)
        rest = rest[domain_length+1:]
    return parts, rest[1:]


def parse_resource_record(record):
    name, rest = get_domain(record)
    record_type, cls, ttl, rdlength = struct.unpack("!HHIH", rest[:10])
    rdata = rest[10:10+rdlength]
    # TODO: parse ns record
    #if record_type == 2: # NS record?
    #    rdata, _ = get_domain(rdata)
    rest = rest[10+rdlength:]
    return ResponseRecord(record_type, cls, ttl, rdlength, rdata), rest

def create_dns_query(query_id, parts):
    query = struct.pack('!HHHHHH', query_id, 288, 1, 0, 0, 0)
    query += create_question(parts)
    return query

def create_question(parts):
    query = create_domain(parts)
    query += struct.pack("!HH", 1, 1) # A, internet
    return query

def create_response(query_id, parts, ip, ttl):
    query = struct.pack('!HHHHHH', query_id, 33152, 1, 1, 0, 0)
    query += create_question(parts)
    # answer
    query += create_domain(parts)
    query += struct.pack("!HHIH", 1, 1, ttl, 4)
    query += ip
    return query

def get_response(server, parts):
    msg_id = random.randint(1, 2**16 - 1)
    query = create_dns_query(msg_id, parts)
    with udp_socket() as s:
        s.sendto(query, (server, 53))
        result, _ = s.recvfrom(65000)
        return parse_dns_packet(result)

def create_domain(parts):
    query = b''
    for part in parts:
        query += struct.pack('!B', len(part))
        query += part
    query += b'\x00'
    return query

def get_ip(packet):
    for part in packet.answers:
        if part.record_type == 1:
            return part.data, part.ttl
    for part in packet.additionals:
        if part.record_type == 1:
            return part.data, part.ttl

def parse_data_ip(ip):
    return '.'.join([str(x) for x in struct.unpack('!BBBB', ip)])

def get_ns(packet):
    for part in packet.authorities:
        if part.record_type == 2:
            parts, _ = get_domain(part.data)
            return parts


def recurse(parts):
    print(parts)
    ip = '198.41.0.4'
    for i in range(3): # this hardcoded 3 is probably wrong but who cares, it works
        if type(ip) is str:
            packet = get_response(ip, parts)
        else:
            packet = get_response(parse_data_ip(ip), parts)
        retval = get_ip(packet)
        if retval is None:
            ns = get_ns(packet)
            ip, ttl = recurse(ns)
        else:
            ip, ttl = retval
    return ip, ttl

if __name__ == "__main__":
    run()
