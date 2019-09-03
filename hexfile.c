// hexfile related functions

#include <stdio.h>
#include <string.h>
#include <ctype.h>


static const char hex_chars[] = "0123456789ABCDEF";


// func: hex_highchar
// desc: returns a character containing the high nibble of
// a value. e.g. A2H -> 'A'
// passed: value
// returns: character
#define hex_highchar(value) (hex_chars[((value) >> 4) & 0x0f])


// func: hex_lowchar
// desc: returns a character containing the low nibble of
// a value. e.g. A2H -> '2'
// passed: value
// returns: character
#define hex_lowchar(value) (hex_chars[(value) & 0x0f])


// func: hex_char16
// desc: returns a character containing a specific nibble of a
// 16-bit value. e.g. A2B3H -> pos 0 = 'A', pos 3 = '3'
// passed: value and nibble number 0 - 3
// returns: character
#define hex_char16(value, pos) (hex_chars[((value) >> (4 * (3 - (pos)))) & 0x0f])

// func: hex_calculate_value
// desc: takes two chars such as '4' and 'A' and converts them to the
// hex value 4AH
// passed: high and low characters
// returns: 8-bit value
unsigned char hex_calculate_value(unsigned char high, unsigned char low)
{
	unsigned char value, nibble;

	nibble = high - '0';
	if (nibble > 9 && nibble < 23) nibble -= 7;
	if(nibble > 22) nibble -= 39;
	value = (16 * nibble);

	nibble = low - '0';
	if (nibble > 9 && nibble < 23) nibble -= 7;
	if (nibble > 22) nibble -= 39;
	value += nibble;

	return value;
}

// func: hexfile_calculate_checksum
// desc: calculates checksum based on hex file data
// passed: pointer to buffer containing hexfile data, number of bytes of data
// returns: checksum
unsigned char hexfile_calculate_checksum(unsigned char *buffer, int bytes)
{
	int checksum = 0;
	int i;

	for (i = 1; i < bytes; i+=2)
	{
		checksum += hex_calculate_value(buffer[i], buffer[i+1]);
	}

	checksum = 0x100 - (unsigned char)checksum;

	return (unsigned char) checksum;
}


// write Extended Linear Address (type 04) record to output buffer
// and return number of bytes written including line terminating characters
unsigned make_type04(unsigned addr, char* outbuff)
{
    unsigned off = 0;
    int t = sprintf(outbuff, ":02000004%04X", addr >> 16);
    if(t <= 0) return 0;
    off = t;
    unsigned char checksum = hexfile_calculate_checksum(outbuff, off);
    t = sprintf(outbuff + off, "%02X\n", checksum);
    if(t <= 0) return 0;
	off += t;
	return off;
}


// write Data (type 00) record to output buffer
// and return number of bytes written including line terminating characters
unsigned make_type00(unsigned addr, int bytes, unsigned char *inbuff, char *outbuff)
{
    unsigned off = 0;

    // write header for type 00
    int t = sprintf(outbuff, ":%02X%04X00", bytes, addr & 0xffff);
    if(t <= 0) return 0;
    off = t;
    int i;
    for(i = 0; i < bytes; i++)
    {
        t = sprintf(outbuff + off, "%02X", inbuff[i]);
        if(t <= 0) return 0;
        off += t;
    }
    unsigned char checksum = hexfile_calculate_checksum(outbuff, off);
    t = sprintf(outbuff + off, "%02X\n", checksum);
    if(t <= 0) return 0;
	off += t;
	return off;
}


// write End Of File (type 01) record to output buffer
// and return number of bytes written including line terminating characters
unsigned make_type01(char* outbuff)
{
    unsigned off = 0;
    int t = sprintf(outbuff, ":00000001FF\n");
    if(t <= 0) return 0;
    off = t;
    return off;
}



// func: hexfile_generate_record
// desc: converts raw data in inbuffer into a hex record in outbuffer
// passed: starting address for record, number of bytes in record, input and output buffers
// returns: nothing
// Note: if addr is <= 0xffff only Data record is generated (type 00)
// Note: if addr is > 0xffff Extended Linear Address (type 04) is generated before Data record (type 00)
// Note: in the worst case outbuffer must have size of 83 + 2 * N bytes for N bytes in inbuffer, so
// for 64 byte inbuffer we need 211 bytes
void hexfile_generate_record(unsigned int addr, int bytes, unsigned char *inbuffer, char *outbuffer)
{
	unsigned offset = 0;

	// if start address is above 64KB we have to use extended address records
	if(addr > 0xffff)
    {
        offset = make_type04(addr, outbuffer);
    }

	while(bytes > 0)
    {
        // calculate length of the next chunk of data
        // up to 16 bytes and to the next 64KB crossing
        unsigned chunk = 0x10000U - (addr & 0xffffU);
        if(chunk > bytes) chunk = bytes;
        if(chunk > 16) chunk = 16;

        // write chunk of data as type 00 (Data) record
        unsigned t = make_type00(addr, chunk, inbuffer, outbuffer + offset);
        if(!t) break;
        offset += t;
        inbuffer += chunk;
        bytes -= chunk;
        addr += chunk;

        // if we have more data to process and we are at 64KB border we have to write record type 04
        if(bytes && !(addr & 0xffff))
        {
            t = make_type04(addr, outbuffer + offset);
            if(!t) break;
            offset += t;
        }
    }

    if(!bytes)
    {
        // if everything is OK we will finish with End Of File record (type 01)
        make_type01(outbuffer + offset);
    }
}
