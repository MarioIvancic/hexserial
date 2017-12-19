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
	long checksum = 0;
	int i;

	for (i = 1; i < bytes; i+=2)
	{
		checksum += hex_calculate_value(buffer[i], buffer[i+1]);
	}

	checksum = 0x100 - (unsigned char)checksum;

	return (unsigned char) checksum;
}

// func: hexfile_generate_record
// desc: converts raw data in inbuffer into a hex record in outbuffer
// passed: starting address for record, number of bytes in record, input and output buffers
// returns: nothing
void hexfile_generate_record(unsigned int addr, int bytes, unsigned char *inbuffer, char *outbuffer)
{
	int byte;
	unsigned char checksum;

	outbuffer[0] = ':';
	outbuffer[1] = hex_highchar((unsigned char)bytes);
	outbuffer[2] = hex_lowchar((unsigned char)bytes);
	outbuffer[3] = hex_char16(addr, 0);
	outbuffer[4] = hex_char16(addr, 1);
	outbuffer[5] = hex_char16(addr, 2);
	outbuffer[6] = hex_char16(addr, 3);
	outbuffer[7] = '0';
	outbuffer[8] = '0';

	for (byte = 0; byte < bytes; byte++)
	{
		outbuffer[9 + (byte * 2)] = hex_highchar(inbuffer[byte]);
		outbuffer[10 + (byte * 2)] = hex_lowchar(inbuffer[byte]);
	}
	checksum = hexfile_calculate_checksum(outbuffer, 9 + (bytes * 2));
	outbuffer[9 + (bytes * 2)] = hex_highchar(checksum);
	outbuffer[10 + (bytes * 2)] = hex_lowchar(checksum);
	outbuffer[11 + (bytes * 2)] = 0;
}
