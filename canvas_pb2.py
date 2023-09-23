from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
_sym_db = _symbol_database.Default()
DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x13protos/canvas.proto\x12\x17\x63om.spotify.canvazcache\"3\n\x06\x41rtist\x12\x0b\n\x03uri\x18\x01 \x01(\t\x12\x0c\n\x04name\x18\x02 \x01(\t\x12\x0e\n\x06\x61vatar\x18\x03 \x01(\t\"\xe6\x02\n\x14\x45ntityCanvazResponse\x12\x46\n\x08\x63\x61nvases\x18\x01 \x03(\x0b\x32\x34.com.spotify.canvazcache.EntityCanvazResponse.Canvaz\x12\x16\n\x0ettl_in_seconds\x18\x02 \x01(\x03\x1a\xed\x01\n\x06\x43\x61nvaz\x12\n\n\x02id\x18\x01 \x01(\t\x12\x0b\n\x03url\x18\x02 \x01(\t\x12\x0f\n\x07\x66ile_id\x18\x03 \x01(\t\x12+\n\x04type\x18\x04 \x01(\x0e\x32\x1d.com.spotify.canvazcache.Type\x12\x12\n\nentity_uri\x18\x05 \x01(\t\x12/\n\x06\x61rtist\x18\x06 \x01(\x0b\x32\x1f.com.spotify.canvazcache.Artist\x12\x10\n\x08\x65xplicit\x18\x07 \x01(\x08\x12\x13\n\x0buploaded_by\x18\x08 \x01(\t\x12\x0c\n\x04\x65tag\x18\t \x01(\t\x12\x12\n\ncanvas_uri\x18\x0b \x01(\t\"\x88\x01\n\x13\x45ntityCanvazRequest\x12\x45\n\x08\x65ntities\x18\x01 \x03(\x0b\x32\x33.com.spotify.canvazcache.EntityCanvazRequest.Entity\x1a*\n\x06\x45ntity\x12\x12\n\nentity_uri\x18\x01 \x01(\t\x12\x0c\n\x04\x65tag\x18\x02 \x01(\t*R\n\x04Type\x12\t\n\x05IMAGE\x10\x00\x12\t\n\x05VIDEO\x10\x01\x12\x11\n\rVIDEO_LOOPING\x10\x02\x12\x18\n\x14VIDEO_LOOPING_RANDOM\x10\x03\x12\x07\n\x03GIF\x10\x04\x42\x16\n\x12\x63om.spotify.canvazH\x02\x62\x06proto3')
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'protos.canvas_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:
  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'\n\022com.spotify.canvazH\002'
  _TYPE._serialized_start=601
  _TYPE._serialized_end=683
  _ARTIST._serialized_start=48
  _ARTIST._serialized_end=99
  _ENTITYCANVAZRESPONSE._serialized_start=102
  _ENTITYCANVAZRESPONSE._serialized_end=460
  _ENTITYCANVAZRESPONSE_CANVAZ._serialized_start=223
  _ENTITYCANVAZRESPONSE_CANVAZ._serialized_end=460
  _ENTITYCANVAZREQUEST._serialized_start=463
  _ENTITYCANVAZREQUEST._serialized_end=599
  _ENTITYCANVAZREQUEST_ENTITY._serialized_start=557
  _ENTITYCANVAZREQUEST_ENTITY._serialized_end=599
