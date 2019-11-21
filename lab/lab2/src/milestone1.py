#build a secure layer on top of reliable layer: allow data unencrypted to transport
#handshake end: send certificate[legitimate] in bo the direction and mutual authentication
from playground.network.common import StackingProtocolFactory, StackingProtocol, StackingTransport
import logging

from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import STRING, UINT8, UINT16, UINT32, BUFFER, BOOL
from playground.network.packet.fieldtypes.attributes import Optional

import random
import datetime

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .poop.protocol import PassthroughProtocol

logger = logging.getLogger("playground.__connector__."+__name__)
#Define Packet
class CrapPacketType(PacketType):
    DEFINITION_IDENTIFIER = "crap"
    DEFINITION_VERSION = "1.0"

class HandshakePacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.handshakepacket"
    DEFINITION_VERSION = "1.0"

    NOT_STARTED = 0
    SUCCESS     = 1
    ERROR       = 2

    FIELDS = [
        ("status", UINT8),
        ("nonce", UINT32({Optional:True})),
        ("nonceSignature", BUFFER({Optional:True})),
        ("signature", BUFFER({Optional:True})),
        ("pk", BUFFER({Optional:True})),
        ("cert", BUFFER({Optional:True}))
    ]

class DataPacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.datapacket"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("data", BUFFER),
        ("signature", BUFFER),
    ]

class CrapTransport(StackingTransport):
    def __init__(self, transport, protocol):
        super().__init__(transport)
        self.protocol = protocol
        self.confirmed_seqs = {}

    def write(self, data):
        self.protocol.myWrite(data)

    def close(self):
        self.protocol.myClose()

class CrapTransport(StackingTransport):
    def __init__(self, transport, protocol):
        super().__init__(transport)
        self.protocol = protocol
        self.confirmed_seqs = {}

    def write(self, data):
        self.protocol.myWrite(data)

    def close(self):
        self.protocol.myClose() 

class CrapProtocol(StackingProtocol):
    def __init__(self,mode):
        super().__init__()
        print("Handshake start!")
        self.mode = mode
        #string to data
        self.deserializer = CrapPacketType.Deserializer()
        self._stage = "handshake"
    
    #Process 1:make connection and let client A send packet1
    def connection_made(self,transport):
        self.transport = transport
        if self.mode == "client":
            print("Client start : send first packet")
            self.connect_handshake()
            self.client_send_packet1()
            print("Client finish : send first packet")

    def connect_handshake(self):
        #step1:generate private and public key
        self.privA = ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.pubA = self.privA.public_key()
        self.pubA_ser = self.pubA.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        #step2:generate certificate and sign
        self.certA, self.sigkA = self.gen_cert()
        #step3:signature using public key and sign
        self.sigA = self.sigkA.sign(self.pubA_ser, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        #step4:genarate nonce and send 1st packet
        self.nonceA = random.randint(0,2**32)

    def client_send_packet1(self):    
        client_packet1 = HandshakePacket(status=0, nonce=self.nonceA, signature=self.sigA, pk=self.pubA_ser, cert=self.certA)
        self.transport.write(client_packet1.__serialize__())

    #receive data according to server and client
    def data_received(self, buffer):
        print("Start : receive data")
        self.deserializer.update(buffer)
        for packet in self.deserializer.nextPackets():
            #Process2: server B receive packet from client A  
            if self.mode == "server":
                self.data_received_server(packet)
            #Process3: client A receive packet from server B
            elif self.mode == "client":
                self.data_received_client(packet)
        print("Finish : receive data")

    def gen_cert(self):
        #Use RSA to generate a private key
        signk = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"MD"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Baltimore"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Team6"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"Gaoyuan"),
        ])

        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(signk.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10)
            # Sign our certificate with our private key
            ).sign(signk, hashes.SHA256(), default_backend())
        #serial    
        cert_ser = cert.public_bytes(serialization.Encoding.PEM)
        return cert_ser, signk

    #Process2: server B receive packet from client A 
    def data_received_server(self, packet):
        print("Process2: server B receive packet from client A")
        #Process2: Packet from client A doesn't have nonceSignature
        if not packet.nonceSignature:
            print("Server start: send 2nd packet")
            #step1: Server B verify sigA of packet
            self.server_verify_handshake(packet)
            self.server_send_packet2()
            print("Server finish: send 2nd packet")
        #Process4: Packet from client A has nonceSignature
        else:
            #step1: B verify nonceSignatureA using nonceB and certA of packet received
            self.server_verify_nonce(packet,self.nonceB)
            self._stage = "connected"
            print(self._stage)

    def server_verify_handshake(self, packet)
        self.server_verify_sigA(packet)
        #step2: Server B generate pub and priv key
        self.privB = ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.pubB = self.privB.public_key()
        self.pubB_ser = self.pubB.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        #step3: B calculate shared key by pubA and privB
        self.sharedB = self.privB.exchange(ec.ECDH(), load_pem_public_key(packet.pk, default_backend())) 
        #step4: B generate certificate and signature key
        self.certB, self.sigkB = self.gen_cert()
        #step5: B generate sigB by pubB and signature key in step4
        self.sigB = self.sigkB.sign(self.pubB_ser,padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        #step6: B generate nonceSignatureB by sigkB and nonceA
        self.nonceSignatureB = self.gen_noncesig(packet, self.sigkB)
        #step7: B generate nonceB and send packet to client A.
        self.nonceB = random.randint(0,2**32)

    def server_send_packet2(self):    
        server_packet2 = HandshakePacket(status=1, nonce=self.nonceB, nonceSignature = self.nonceSignatureB, signature=self.sigB, pk=self.pubB_ser, cert=self.certB)
        self.transport.write(server_packet2.__serialize__())

    #Process3: Client A receive packet from server B and send packet agian.
    def data_received_client(self,packet):
        print("Process3: client A receive packet from server B") 
        print("Client start: send 3rd packet")
        self.client_verify_handshake(packet)  
        #step5: A send packet3 to B
        self.client_send_packet3()
        self._stage = "connected"
        print(self._stage)
        print("Client finish: send 3rd packet")

    def client_verify_handshake(self, packet):
        #step1: A verify signatureB using packet received
        self.client_verify_sigB(packet)
        #step2: A verify nonceSignatureB using nonce A and received packet
        self.client_verify_nonce(packet,self.nonceA)
        #step3: A generate shared key using pubB of packet received and privA
        self.sharedB = self.privA.exchange(ec.ECDH(), load_pem_public_key(packet.pk, default_backend())) 
        #step4: A generate nonceSignatureA using signature key A
        self.certA, self.sigkA = self.gen_cert()
        self.nonceSignatureA = self.gen_noncesig(packet,self.sigkA)

    def client_send_packet3(self):
        client_packet3 = HandshakePacket(status=1, nonceSignature = self.nonceSignatureA)
        self.transport.write(client_packet3.__serialize__())

    def gen_noncesig(self, packet, signk):    
        nonceSignature = signk.sign(str(packet.nonce).encode('ASCII'), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return nonceSignature

    def server_verify_sigA(self, packet):    
        #public key of client's cert
        client_cert = x509.load_pem_x509_certificate(packet.cert, default_backend())
        client_cert_pubK = client_cert.public_key()
        try:
            client_cert_pubK.verify(packet.signature, packet.pk, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
        #server B's verification to client A is wrong
        except Exception as e:
            print("Client A's certification is wrong", e)
            client_packet1_err = HandshakePacket(status=2)
            self.transport.write(client_packet1_err.__serialize__())
            self.transport.close()

    def server_verify_nonce(self,packet,nonce):
        client_cert = x509.load_pem_x509_certificate(packet.cert, default_backend())
        client_cert_pubK = client_cert.public_key()
        try:
            client_cert_pubK.verify(packet.nonceSignature, str(nonceA).encode('ASCII'), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
        except Exception as e:
            print("Client verify nonceSignature from server wrong")
            packet_error = HandshakePacket(status=2)
            self.transport.write(packet_error.__serialize__())
            self.transport.close()

    def client_verify_sigB(self, packet):    
        #public key of server's cert
        server_cert = x509.load_pem_x509_certificate(packet.cert, default_backend())
        server_cert_pubK = server_cert.public_key()
        try:
            server_cert_pubK.verify(packet.signature, packet.pk, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        #client A's verification to server B is wrong
        except Exception as e:
            print("Server B's certification is wrong", e)
            server_packet2_err = HandshakePacket(status=2)
            self.transport.write(server_packet2_err.__serialize__())
            self.transport.close()

    def client_verify_nonce(self,packet,nonce):
        server_cert = x509.load_pem_x509_certificate(packet.cert, default_backend())
        server_cert_pubK = server_cert.public_key()
        
        try:
            server_cert_pubK.verify(packet.nonceSignature, str(nonceA).encode('ASCII'), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        except Exception as e:
            print("Client verify nonceSignature from server wrong")
            packet_error = HandshakePacket(status=2)
            self.transport.write(packet_error.__serialize__())
            self.transport.close()

SecureClientFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: PassthroughProtocol(mode="client"),
    lambda: CrapProtocol(mode="client")
    )
SecureServerFactory = StackingProtocolFactory.CreateFactoryType(
    lambda: PassthroughProtocol(mode="server"),
    lambda: CrapProtocol(mode="server")
)
