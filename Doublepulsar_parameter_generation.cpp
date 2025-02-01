#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void INT2LE(uint32_t data, uint8_t* b) {
    b[0] = (uint8_t)(data & 0xFF);
    b[1] = (uint8_t)((data >> 8) & 0xFF);
    b[2] = (uint8_t)((data >> 16) & 0xFF);
    b[3] = (uint8_t)((data >> 24) & 0xFF);
}

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

int main() {
    uint32_t number = 0x5858626a;
    uint8_t bytes[4];

    INT2LE(number, bytes);

    printf("Bytes: %02X %02X %02X %02X\n", bytes[0], bytes[1], bytes[2], bytes[3]);
    
    
    
    unsigned int XorKey = 0x58581162;
    unsigned int TotalSizeOfPayload = 0x507308; //in the future, we may make this value dynamic based on the len of the shellcode if it's less than 4096
   unsigned int ChunkSize = 4096; //in the future, we may make this value dynamic based on the len of the shellcode if it's less than 4096
   unsigned int OffsetofChunkinPayload = 0;
   unsigned char Parametersbuffer[13];
  memset(Parametersbuffer, 0x00, 13);

   unsigned char pTotalSizeOfPayload[4];
   unsigned char pChunkSize[4];
   unsigned char pOffsetofChunkinPayload[4];
   
  INT2LE(TotalSizeOfPayload, pTotalSizeOfPayload);
  INT2LE(ChunkSize, pChunkSize);
  INT2LE(OffsetofChunkinPayload, pOffsetofChunkinPayload);
  hexDump(0, pTotalSizeOfPayload, 4);
  hexDump(0, pChunkSize, 4);
  hexDump(0, pOffsetofChunkinPayload, 4);

  hexDump(0, Parametersbuffer, 12);
  memcpy((unsigned char*)Parametersbuffer, (unsigned char*)pTotalSizeOfPayload, 4); //0 1 2 3
  memcpy((unsigned char*)Parametersbuffer + 4, (unsigned char*)pChunkSize, 4); //4 5 6 7
  memcpy((unsigned char*)Parametersbuffer + 8, (unsigned char*)pOffsetofChunkinPayload, 4); //8 9 10 11
  
  unsigned char byte_xor_key[5];
	byte_xor_key[0] = (unsigned char)XorKey;
	byte_xor_key[1] = (unsigned char)(((unsigned int)XorKey >> 8) & 0xFF);
	byte_xor_key[2] = (unsigned char)(((unsigned int)XorKey >> 16) & 0xFF);
	byte_xor_key[3] = (unsigned char)(((unsigned int)XorKey >> 24) & 0xFF);
	
  int i;
  for (i = 0; i < 13; i++)
  {
     Parametersbuffer[i] ^= byte_xor_key[i % 4];
  }
  hexDump(0, Parametersbuffer, 12);


  return 0;
}
