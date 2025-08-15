import argparse
import binascii
import struct
import zlib


def read_png_chunks(file_path):
    chunks = []
    with open(file_path, "rb") as f:
        png_header = f.read(8)
        if png_header != b"\x89PNG\r\n\x1a\n":
            raise Exception("不是有效的PNG文件")
        while True:
            try:
                length = struct.unpack(">I", f.read(4))[0]
                chunk_type = f.read(4)
                data = f.read(length)
                crc = struct.unpack(">I", f.read(4))[0]
                chunks.append(
                    {"length": length, "type": chunk_type, "data": data, "crc": crc}
                )
                if chunk_type == b"IEND":
                    break
            except:
                break
    return chunks


def analyze_idat_chunks(chunks):
    idat_chunks = [chunk for chunk in chunks if chunk["type"] == b"IDAT"]
    print(f"发现 {len(idat_chunks)} 个IDAT块")
    all_data = []
    patterns = ["flag", "ctf", "f14g", "hint", "zmxhz"]
    found_any = False

    for i, chunk in enumerate(idat_chunks):
        data = chunk["data"]
        all_data.append(data)
        print(f"IDAT块 #{i+1}: 长度={len(data)} CRC={hex(chunk['crc'])}")
        if data.startswith(b"\x78\x9c"):
            try:
                decompressed = zlib.decompress(data)
                text = decompressed.decode("utf-8", errors="replace")
                lower = text.lower()
                for pat in patterns:
                    if pat in lower:
                        print(f"\n在 IDAT 块 #{i+1} 中匹配到 '{pat}'，完整解码内容：\n")
                        print(text)
                        found_any = True
                        break
            except:
                pass
    try:
        full_stream = b"".join(all_data)
        decompressed_full = zlib.decompress(full_stream)
        text_full = decompressed_full.decode("utf-8", errors="replace")
        lower_full = text_full.lower()
        for pat in patterns:
            if pat in lower_full:
                print(f"\n在拼接后的 IDAT 流中匹配到 '{pat}'，完整解码内容：\n")
                print(text_full)
                found_any = True
                break
    except:
        pass
    if not found_any:
        print("未在可解码文本中匹配到常见 flag 字符串")


def analyze_chunks_overview(chunks):
    if not chunks:
        print("未检测到任何块")
        return
    print("\n=== 块类型概览 (顺序) ===")
    type_counts = {}
    for idx, c in enumerate(chunks, 1):
        t = c["type"].decode(errors="replace")
        length = c["length"]
        stored_crc = c["crc"]
        calc_crc = binascii.crc_hqx(b"", 0)
        try:
            calc_crc = binascii.crc32(c["type"] + c["data"]) & 0xFFFFFFFF
        except:
            calc_crc = None
        ok = calc_crc == stored_crc
        print(
            f"{idx:03d}: type={t} length={length} CRC_stored=0x{stored_crc:08x} CRC_calc={('0x%08x' % calc_crc) if calc_crc is not None else 'N/A'} status={'OK' if ok else 'MISMATCH'})"
        )
        type_counts[t] = type_counts.get(t, 0) + 1
    print("\n块类型统计:")
    for t, cnt in type_counts.items():
        print(f"{t}: {cnt}")


def main():
    parser = argparse.ArgumentParser(description="分析 PNG 的 IDAT 块")
    parser.add_argument(
        "-f",
        "--file",
        dest="file",
        default="image.png",
        help="要分析的 PNG 文件路径，默认为当前路径下的 image.png",
    )
    args = parser.parse_args()
    file_path = args.file
    print(f"分析文件: {file_path}")
    chunks = read_png_chunks(file_path)
    analyze_chunks_overview(chunks)
    analyze_idat_chunks(chunks)


if __name__ == "__main__":
    main()
