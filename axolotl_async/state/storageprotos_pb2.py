# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: LocalStorageProtocol.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x1aLocalStorageProtocol.proto\x12\ntextsecure\"\xd3\x08\n\x10SessionStructure\x12\x16\n\x0esessionVersion\x18\x01 \x01(\r\x12\x1b\n\x13localIdentityPublic\x18\x02 \x01(\x0c\x12\x1c\n\x14remoteIdentityPublic\x18\x03 \x01(\x0c\x12\x0f\n\x07rootKey\x18\x04 \x01(\x0c\x12\x17\n\x0fpreviousCounter\x18\x05 \x01(\r\x12\x37\n\x0bsenderChain\x18\x06 \x01(\x0b\x32\".textsecure.SessionStructure.Chain\x12:\n\x0ereceiverChains\x18\x07 \x03(\x0b\x32\".textsecure.SessionStructure.Chain\x12K\n\x12pendingKeyExchange\x18\x08 \x01(\x0b\x32/.textsecure.SessionStructure.PendingKeyExchange\x12\x41\n\rpendingPreKey\x18\t \x01(\x0b\x32*.textsecure.SessionStructure.PendingPreKey\x12\x1c\n\x14remoteRegistrationId\x18\n \x01(\r\x12\x1b\n\x13localRegistrationId\x18\x0b \x01(\r\x12\x14\n\x0cneedsRefresh\x18\x0c \x01(\x08\x12\x14\n\x0c\x61liceBaseKey\x18\r \x01(\x0c\x1a\xb9\x02\n\x05\x43hain\x12\x18\n\x10senderRatchetKey\x18\x01 \x01(\x0c\x12\x1f\n\x17senderRatchetKeyPrivate\x18\x02 \x01(\x0c\x12=\n\x08\x63hainKey\x18\x03 \x01(\x0b\x32+.textsecure.SessionStructure.Chain.ChainKey\x12\x42\n\x0bmessageKeys\x18\x04 \x03(\x0b\x32-.textsecure.SessionStructure.Chain.MessageKey\x1a&\n\x08\x43hainKey\x12\r\n\x05index\x18\x01 \x01(\r\x12\x0b\n\x03key\x18\x02 \x01(\x0c\x1aJ\n\nMessageKey\x12\r\n\x05index\x18\x01 \x01(\r\x12\x11\n\tcipherKey\x18\x02 \x01(\x0c\x12\x0e\n\x06macKey\x18\x03 \x01(\x0c\x12\n\n\x02iv\x18\x04 \x01(\x0c\x1a\xcd\x01\n\x12PendingKeyExchange\x12\x10\n\x08sequence\x18\x01 \x01(\r\x12\x14\n\x0clocalBaseKey\x18\x02 \x01(\x0c\x12\x1b\n\x13localBaseKeyPrivate\x18\x03 \x01(\x0c\x12\x17\n\x0flocalRatchetKey\x18\x04 \x01(\x0c\x12\x1e\n\x16localRatchetKeyPrivate\x18\x05 \x01(\x0c\x12\x18\n\x10localIdentityKey\x18\x07 \x01(\x0c\x12\x1f\n\x17localIdentityKeyPrivate\x18\x08 \x01(\x0c\x1aJ\n\rPendingPreKey\x12\x10\n\x08preKeyId\x18\x01 \x01(\r\x12\x16\n\x0esignedPreKeyId\x18\x03 \x01(\x05\x12\x0f\n\x07\x62\x61seKey\x18\x02 \x01(\x0c\"\x7f\n\x0fRecordStructure\x12\x34\n\x0e\x63urrentSession\x18\x01 \x01(\x0b\x32\x1c.textsecure.SessionStructure\x12\x36\n\x10previousSessions\x18\x02 \x03(\x0b\x32\x1c.textsecure.SessionStructure\"J\n\x15PreKeyRecordStructure\x12\n\n\x02id\x18\x01 \x01(\r\x12\x11\n\tpublicKey\x18\x02 \x01(\x0c\x12\x12\n\nprivateKey\x18\x03 \x01(\x0c\"v\n\x1bSignedPreKeyRecordStructure\x12\n\n\x02id\x18\x01 \x01(\r\x12\x11\n\tpublicKey\x18\x02 \x01(\x0c\x12\x12\n\nprivateKey\x18\x03 \x01(\x0c\x12\x11\n\tsignature\x18\x04 \x01(\x0c\x12\x11\n\ttimestamp\x18\x05 \x01(\x06\"A\n\x18IdentityKeyPairStructure\x12\x11\n\tpublicKey\x18\x01 \x01(\x0c\x12\x12\n\nprivateKey\x18\x02 \x01(\x0c\"\xb8\x03\n\x17SenderKeyStateStructure\x12\x13\n\x0bsenderKeyId\x18\x01 \x01(\r\x12J\n\x0esenderChainKey\x18\x02 \x01(\x0b\x32\x32.textsecure.SenderKeyStateStructure.SenderChainKey\x12N\n\x10senderSigningKey\x18\x03 \x01(\x0b\x32\x34.textsecure.SenderKeyStateStructure.SenderSigningKey\x12O\n\x11senderMessageKeys\x18\x04 \x03(\x0b\x32\x34.textsecure.SenderKeyStateStructure.SenderMessageKey\x1a\x31\n\x0eSenderChainKey\x12\x11\n\titeration\x18\x01 \x01(\r\x12\x0c\n\x04seed\x18\x02 \x01(\x0c\x1a\x33\n\x10SenderMessageKey\x12\x11\n\titeration\x18\x01 \x01(\r\x12\x0c\n\x04seed\x18\x02 \x01(\x0c\x1a\x33\n\x10SenderSigningKey\x12\x0e\n\x06public\x18\x01 \x01(\x0c\x12\x0f\n\x07private\x18\x02 \x01(\x0c\"X\n\x18SenderKeyRecordStructure\x12<\n\x0fsenderKeyStates\x18\x01 \x03(\x0b\x32#.textsecure.SenderKeyStateStructureB4\n#org.whispersystems.libaxolotl.stateB\rStorageProtos')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'LocalStorageProtocol_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'\n#org.whispersystems.libaxolotl.stateB\rStorageProtos'
  _SESSIONSTRUCTURE._serialized_start=43
  _SESSIONSTRUCTURE._serialized_end=1150
  _SESSIONSTRUCTURE_CHAIN._serialized_start=553
  _SESSIONSTRUCTURE_CHAIN._serialized_end=866
  _SESSIONSTRUCTURE_CHAIN_CHAINKEY._serialized_start=752
  _SESSIONSTRUCTURE_CHAIN_CHAINKEY._serialized_end=790
  _SESSIONSTRUCTURE_CHAIN_MESSAGEKEY._serialized_start=792
  _SESSIONSTRUCTURE_CHAIN_MESSAGEKEY._serialized_end=866
  _SESSIONSTRUCTURE_PENDINGKEYEXCHANGE._serialized_start=869
  _SESSIONSTRUCTURE_PENDINGKEYEXCHANGE._serialized_end=1074
  _SESSIONSTRUCTURE_PENDINGPREKEY._serialized_start=1076
  _SESSIONSTRUCTURE_PENDINGPREKEY._serialized_end=1150
  _RECORDSTRUCTURE._serialized_start=1152
  _RECORDSTRUCTURE._serialized_end=1279
  _PREKEYRECORDSTRUCTURE._serialized_start=1281
  _PREKEYRECORDSTRUCTURE._serialized_end=1355
  _SIGNEDPREKEYRECORDSTRUCTURE._serialized_start=1357
  _SIGNEDPREKEYRECORDSTRUCTURE._serialized_end=1475
  _IDENTITYKEYPAIRSTRUCTURE._serialized_start=1477
  _IDENTITYKEYPAIRSTRUCTURE._serialized_end=1542
  _SENDERKEYSTATESTRUCTURE._serialized_start=1545
  _SENDERKEYSTATESTRUCTURE._serialized_end=1985
  _SENDERKEYSTATESTRUCTURE_SENDERCHAINKEY._serialized_start=1830
  _SENDERKEYSTATESTRUCTURE_SENDERCHAINKEY._serialized_end=1879
  _SENDERKEYSTATESTRUCTURE_SENDERMESSAGEKEY._serialized_start=1881
  _SENDERKEYSTATESTRUCTURE_SENDERMESSAGEKEY._serialized_end=1932
  _SENDERKEYSTATESTRUCTURE_SENDERSIGNINGKEY._serialized_start=1934
  _SENDERKEYSTATESTRUCTURE_SENDERSIGNINGKEY._serialized_end=1985
  _SENDERKEYRECORDSTRUCTURE._serialized_start=1987
  _SENDERKEYRECORDSTRUCTURE._serialized_end=2075
# @@protoc_insertion_point(module_scope)
