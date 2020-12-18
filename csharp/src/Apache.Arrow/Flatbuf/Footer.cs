// <auto-generated>
//  automatically generated by the FlatBuffers compiler, do not modify
// </auto-generated>

namespace Apache.Arrow.Flatbuf
{

using global::System;
using global::FlatBuffers;

/// ----------------------------------------------------------------------
/// Arrow File metadata
///
internal struct Footer : IFlatbufferObject
{
  private Table __p;
  public ByteBuffer ByteBuffer { get { return __p.bb; } }
  public static Footer GetRootAsFooter(ByteBuffer _bb) { return GetRootAsFooter(_bb, new Footer()); }
  public static Footer GetRootAsFooter(ByteBuffer _bb, Footer obj) { return (obj.__assign(_bb.GetInt(_bb.Position) + _bb.Position, _bb)); }
  public void __init(int _i, ByteBuffer _bb) { __p.bb_pos = _i; __p.bb = _bb; }
  public Footer __assign(int _i, ByteBuffer _bb) { __init(_i, _bb); return this; }

  public MetadataVersion Version { get { int o = __p.__offset(4); return o != 0 ? (MetadataVersion)__p.bb.GetShort(o + __p.bb_pos) : MetadataVersion.V1; } }
  public Schema? Schema { get { int o = __p.__offset(6); return o != 0 ? (Schema?)(new Schema()).__assign(__p.__indirect(o + __p.bb_pos), __p.bb) : null; } }
  public Block? Dictionaries(int j) { int o = __p.__offset(8); return o != 0 ? (Block?)(new Block()).__assign(__p.__vector(o) + j * 24, __p.bb) : null; }
  public int DictionariesLength { get { int o = __p.__offset(8); return o != 0 ? __p.__vector_len(o) : 0; } }
  public Block? RecordBatches(int j) { int o = __p.__offset(10); return o != 0 ? (Block?)(new Block()).__assign(__p.__vector(o) + j * 24, __p.bb) : null; }
  public int RecordBatchesLength { get { int o = __p.__offset(10); return o != 0 ? __p.__vector_len(o) : 0; } }

  public static Offset<Footer> CreateFooter(FlatBufferBuilder builder,
      MetadataVersion version = MetadataVersion.V1,
      Offset<Schema> schemaOffset = default(Offset<Schema>),
      VectorOffset dictionariesOffset = default(VectorOffset),
      VectorOffset recordBatchesOffset = default(VectorOffset)) {
    builder.StartObject(4);
    Footer.AddRecordBatches(builder, recordBatchesOffset);
    Footer.AddDictionaries(builder, dictionariesOffset);
    Footer.AddSchema(builder, schemaOffset);
    Footer.AddVersion(builder, version);
    return Footer.EndFooter(builder);
  }

  public static void StartFooter(FlatBufferBuilder builder) { builder.StartObject(4); }
  public static void AddVersion(FlatBufferBuilder builder, MetadataVersion version) { builder.AddShort(0, (short)version, 0); }
  public static void AddSchema(FlatBufferBuilder builder, Offset<Schema> schemaOffset) { builder.AddOffset(1, schemaOffset.Value, 0); }
  public static void AddDictionaries(FlatBufferBuilder builder, VectorOffset dictionariesOffset) { builder.AddOffset(2, dictionariesOffset.Value, 0); }
  public static void StartDictionariesVector(FlatBufferBuilder builder, int numElems) { builder.StartVector(24, numElems, 8); }
  public static void AddRecordBatches(FlatBufferBuilder builder, VectorOffset recordBatchesOffset) { builder.AddOffset(3, recordBatchesOffset.Value, 0); }
  public static void StartRecordBatchesVector(FlatBufferBuilder builder, int numElems) { builder.StartVector(24, numElems, 8); }
  public static Offset<Footer> EndFooter(FlatBufferBuilder builder) {
    int o = builder.EndObject();
    return new Offset<Footer>(o);
  }
  public static void FinishFooterBuffer(FlatBufferBuilder builder, Offset<Footer> offset) { builder.Finish(offset.Value); }
  public static void FinishSizePrefixedFooterBuffer(FlatBufferBuilder builder, Offset<Footer> offset) { builder.FinishSizePrefixed(offset.Value); }
};


}