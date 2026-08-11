// bin2c.cpp —— 把 payload DLL 转成 C 头文件（内嵌字节数组），实现 BandEdit 单文件分发
// 用法: bin2c <in.dll> <out.h> [数组名]
#include <cstdio>
int main(int argc, char** argv) {
    if (argc < 3) { fprintf(stderr, "usage: bin2c <in.dll> <out.h> [SymName]\n"); return 1; }
    const char* sym = argc >= 4 ? argv[3] : "kEmbeddedPayload";
    FILE* fi = fopen(argv[1], "rb");
    if (!fi) { perror("open in"); return 1; }
    fseek(fi, 0, SEEK_END); long n = ftell(fi); fseek(fi, 0, SEEK_SET);
    if (n <= 0) { fprintf(stderr, "empty input\n"); fclose(fi); return 1; }
    FILE* fo = fopen(argv[2], "w");
    if (!fo) { perror("open out"); fclose(fi); return 1; }
    fprintf(fo, "// 由 bin2c 自动生成 (%ld bytes)，请勿手改 —— 改动需重编 bandedit-x64.exe\n#pragma once\n", n);
    fprintf(fo, "static const unsigned char %s[] = {\n", sym);
    for (long i = 0; i < n; ++i) {
        int c = fgetc(fi);
        if (i % 16 == 0) fputc(' ', fo);
        fprintf(fo, "0x%02X,", c);
        if (i % 16 == 15) fputc('\n', fo);
    }
    fprintf(fo, "\n};\nstatic const unsigned int %sLen = %ld;\n", sym, n);
    fclose(fi); fclose(fo);
    fprintf(stderr, "bin2c: %ld bytes -> %s\n", n, argv[2]);
    return 0;
}
