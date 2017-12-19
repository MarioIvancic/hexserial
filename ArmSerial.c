/**************************************************************
Version 1.06

1.00 - Modifikovano tako da zadnji generisani serijski broj cuva u
registry bazi. Serijski brojevi u bezi zavise od prefixa i
nezavisni su za svaki prefix.

1.01 - Dodat -n parametar na komandnoj liniji za generisanje HEX fajla
bez inkrementovanja brojaca u registry bazi

1.02 - Dodat -p parametar na komandnoj liniji za printanje serial
stringa na stdio

1.03 - Dodat -f parametar na komandnoj liniji da se forsira serijski broj
Dodat -u parametar na komandnoj liniji da se serijski broj dat
sa -f spremi u registry bazu. Koristi se samo zajedno sa -f

Serijski broj se sastoji od rednog broja, timestamp stringa i proizvoljnog
prefixa.
- Prefix moze biti bilo koji string bez praznina do 5 karaktera duzine. Ako je
prefix duzi odsjeca se na 5 karaktera.
- Time stamp sadrzi 14 ASCII cifara i ima format YYYYMMDDHHMMSS.
- Redni broj se sastoji od 10 decimalnih cifara i moze biti u opsegu od
0000000001 do 4294967295.
Sve zajedno: PPPPP-YYYYMMDDHHmmSS-RRRRRRRRRR

1.04 - Modifikovan je format serijskog broja tako sto je povecana duzina
prefixa sa 5 na 9 karaktera a smanjena duzina serijskog broja sa 10 na 6 cifara.
U komandnom fajlu se # ili ; na pocetku linije koriste da oznace komentar

Serijski broj se sastoji od rednog broja, timestamp stringa i proizvoljnog
prefixa.
- Prefix moze biti bilo koji string bez praznina do 9 karaktera duzine. Ako je
prefix duzi odsjeca se na 9 karaktera.
- Time stamp sadrzi 14 ASCII cifara i ima format YYYYMMDDHHMMSS.
- Redni broj se sastoji od 6 decimalnih cifara i moze biti u opsegu od
000001 do 999999.
Sve zajedno: PPPPPPPPP-YYYYMMDDHHmmSS-RRRRRR

1.05 - Dodata je -F opcija da se umjesto u registry podaci cuvaju u fajlu.
To je bitno zbog sigurnosnih razloga kada se podaci trebaju cuvati zajedno sa HEX kodom.

1.06 - Svi globalni parametri prebaceni u strukturu hex_cfg

**************************************************************/

#define VERSION_STRING "1.06"

// include needed header files
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "hexfile.h"


#ifndef MAX_PATH
#define MAX_PATH 2048
#endif


typedef struct hex_cfg
{
    // location in flash memory to store serial number at
    unsigned int address;

    // flag za inkrementovanje serijskog broja u registry bazi
    int increment; // po defaultu se inkrementuje

    // flag za update stanja u registry bazi
    int update;

    // flag za forsiranje serijskog broja
    int force;

    // vrijednost forsiranog serijskog broja
    unsigned int forced_serial;

    // koristi se fajl umjesto registry baze
    char* last_serial_file;

    char* datafilepath;
	char* userfilepath;

    // array to hold serial number/datestamp
    char serialnumber[32];

    // prefix serijskog broja
    char* serialprefix;
} hex_cfg;


void hex_cfg_init(hex_cfg* cfg)
{
    memset(cfg, 0, sizeof(hex_cfg));
    cfg->increment = 1;
}


// vraca vrijednost > 0 ako je sve ok, 0 ako nema vrijednosti
// < 0 ako je neka greska
int get_last_file_value(char* last_serial_file)
{
    FILE* fp;
    int value, size;
    char bkp_file_name[MAX_PATH];

    if(!last_serial_file) return -1;

    fp = fopen(last_serial_file, "rb");

    if(!fp) return 0; // nema fajla, kao da je bila 0

    size = fread(&value, sizeof(int), 1, fp);
    fclose(fp);

    if(size != 1) return -2; // greska pri citanju
    if(value < 0) return -3; // pogresna vrijednost, greska

    // pravi se bekap fajl
    strcpy(bkp_file_name, last_serial_file);
    strcat(bkp_file_name, ".bkp");
    fp = fopen(bkp_file_name, "wb");
    if(fp)
    {
        fwrite(&value, sizeof(int), 1, fp);
        fclose(fp);
    }

    return value;
}


// vraca vrijednost >= 0 ako je sve ok,
// < 0 ako je neka greska
int set_last_file_value(char* last_serial_file, int value)
{
    FILE* fp;
    int size;

    if(!last_serial_file) return -4;

    fp = fopen(last_serial_file, "wb");
    if(!fp) return -5; // greska

    size = fwrite(&value, sizeof(int), 1, fp);
    fclose(fp);
    if(size != 1)
    {
        // upis nije uspio, brisem fajl
        printf("Upis nije uspio: upisano %d a treba %d bajta, brisem fajl\n", size, 1);
        unlink(last_serial_file);
        return -6;
    }
    return 0; // ok
}



// function to generate the actual serial number and put it into
// an intel hex record ready for programming
// outputfile = handle of file to write hex record
int generate(FILE *outputfile, hex_cfg* cfg)
{
	char hexrecord[100];
	unsigned long now;
	int  serial;
	struct tm* timedate;

    serial = get_last_file_value(cfg->last_serial_file);
    // zadnji serijski broj je u serial

    if(serial < 0) return serial; // greska
	if(cfg->force) serial = cfg->forced_serial; // ako se forsira serial
    else if(cfg->increment) serial++; // za 1 veci

    // ako se inkrementira ili ako se forsira i apdejtuje
	// upisuje se nova vrijednost u registry
	if(cfg->increment || (cfg->force && cfg->update))
	{
		int r;
		r = set_last_file_value(cfg->last_serial_file, serial);
		if(r < 0) return r; // ako nije uspjelo ...
	}

	// get the current time
	time((time_t *)&now);

	timedate = localtime(&now);

	// store current time in serial number array
	sprintf(
		cfg->serialnumber,
		"%s-%04d%02d%02d%02d%02d%02d-%06u",
		cfg->serialprefix,
		1900 + timedate->tm_year,
		1 + timedate->tm_mon,
		timedate->tm_mday,
		timedate->tm_hour,
		timedate->tm_min,
		timedate->tm_sec,
		serial);

	// create a hex record holding the serial number
	hexfile_generate_record(
		cfg->address,
		strlen(cfg->serialnumber) + 1, // ovaj 1 jer se koduje i terminacioni \0 karakter
		cfg->serialnumber,
		hexrecord);

	// output the hex record
	fprintf(outputfile, "%s\n", hexrecord);

	return 0; // OK
}


void usage(void)
{
    fprintf(stderr,"HexSerial, version %s, compiled at %s\n", VERSION_STRING, __DATE__);
	fprintf(stderr,"Usage: -a n -l f -h f -p f [-t f] [-n] [-u] [-f n]\n");
	fprintf(stderr,"Options: -n     don't increment sequence number\n");
	fprintf(stderr,"         -u     update last serial file with forced value\n");
	fprintf(stderr,"         -a n   serial string address in HEX file in HEX notation with 0x prefix\n");
	fprintf(stderr,"         -f n   force sequence number to n\n");
	fprintf(stderr,"         -l f   last serial file\n");
	fprintf(stderr,"         -h f   output hex file\n");
	fprintf(stderr,"         -t f   output text file\n");
	fprintf(stderr,"         -p f   serial prefix\n");
	fprintf(stderr,"\n");
}


// main function
int main(int argc, char **argv)
{
	FILE *datafile;
	hex_cfg cfg;
	int i;

	hex_cfg_init(&cfg);

	// if we didn't receive 3 arguments then we can't do anything (-f -u -l)
	if(argc < 3)
	{
	    usage();
		return 1; // FAIL
	}

	for(i = 0; i < argc; i++)
	{
		if(argv[i][0] == '-')
		{
			if(argv[i][1] == 'n') cfg.increment = 0; // nema inkrementovanja
			else if(argv[i][1] == 'l')
			{
			    if(argv[i][2] != 0) // -l<file>
				{
					cfg.last_serial_file = &argv[i][2];
				}
				else if(i + 1 < argc && argv[i + 1][0] != '-') // -l <file>
				{
					cfg.last_serial_file = argv[i + 1];
					i++;
				}
			}
			else if(argv[i][1] == 'h')
			{
			    if(argv[i][2] != 0) // -h<file>
				{
					cfg.datafilepath = &argv[i][2];
				}
				else if(i + 1 < argc && argv[i + 1][0] != '-') // -h <file>
				{
					cfg.datafilepath = argv[i + 1];
					i++;
				}
			}
			else if(argv[i][1] == 't')
			{
			    if(argv[i][2] != 0) // -t<file>
				{
					cfg.userfilepath = &argv[i][2];
				}
				else if(i + 1 < argc && argv[i + 1][0] != '-') // -t <file>
				{
					cfg.userfilepath = argv[i + 1];
					i++;
				}
			}
			else if(argv[i][1] == 'a')
			{
			    if(strncmp(argv[i], "-a0x", 4) == 0) // -a0x<addr>
			    {
					sscanf(argv[i],"-a0x%x",(unsigned int*)&cfg.address);
				}
				else if(argv[i][2] != 0) // -a<addr>
				{
				    sscanf(argv[i],"-a%d",(unsigned int*)&cfg.address);
				}
				else if(i + 1 < argc && argv[i + 1][0] != '-') // -a <file>
				{
				    if(strncmp(argv[i + 1], "0x", 2) == 0)
                        sscanf(argv[i + 1],"0x%x",(unsigned int*)&cfg.address);
                    else sscanf(argv[i + 1],"%d",(unsigned int*)&cfg.address);
					i++;
				}
			}
			else if(argv[i][1] == 'p')
			{
			    if(argv[i][2] != 0) // -p<file>
				{
					cfg.serialprefix = &argv[i][2];
					if(strlen(cfg.serialprefix) > 9) cfg.serialprefix[9] = 0; // ogranicava se prefix na 9 karaktera
				}
				else if(i + 1 < argc && argv[i + 1][0] != '-') // -p <file>
				{
					cfg.serialprefix = argv[i + 1];
					if(strlen(cfg.serialprefix) > 9) cfg.serialprefix[9] = 0; // ogranicava se prefix na 9 karaktera
					i++;
				}
			}
			else if(argv[i][1] == 'f') // force
			{
				if(argv[i][2] != 0) // -f<serial>
				{
					cfg.forced_serial = strtoul(&argv[i][2],0,0);
				}
				else if(i + 1 < argc && argv[i + 1][0] != '-') // -f <serial>
				{
					cfg.forced_serial = strtoul(argv[i + 1],0,0);
					i++;
				}
				if(cfg.forced_serial && cfg.forced_serial != 0xffffffffUL) cfg.force = 1;
			}
			else if(argv[i][1] == 'u') cfg.update = 1;
			// nepoznata opcija se ignorise
		}
	}

	if(cfg.address == 0)
	{
	    fprintf(stderr, "Invalid patch address\n");
	    return 1;
	}

	if(cfg.datafilepath == 0)
	{
	    fprintf(stderr, "Hex file path invalid or missing\n");
	    return 1;
	}

	if(cfg.last_serial_file == 0)
	{
	    fprintf(stderr, "Last serial file path invalid or missing\n");
	    return 1;
	}

	if(cfg.serialprefix == 0)
	{
	    fprintf(stderr, "Serial prefix invalid or missing\n");
	    return 1;
	}

	// create file for hex records and generate records
	datafile = fopen(cfg.datafilepath, "wb");
	if(!datafile)
	{
	    fprintf(stderr, "Can't open file %s\n", cfg.datafilepath);
	    return 1;
	}

	if((i = generate(datafile, &cfg)) < 0)
	{
	    fprintf(stderr, "Can't generate HEX patch. ErrorCode %d\n", i);
	    return 1; // FAIL
	}

	fclose(datafile);

	// create file for user output and put something in there
	if(cfg.userfilepath)
	{
        FILE* userfile = fopen(cfg.userfilepath, "w");
        if(!userfile)
        {
            fprintf(stderr, "Can't open file %s\n", cfg.userfilepath);
            return 1;
        }

        // generate some feedback for the user
        // in this case we tell the user what the serial number generated
        // is so it can be noted and maybe put on a sticker somewhere
        fprintf(userfile, "%s\n", cfg.serialnumber);
        fclose(userfile);
	}

	// if requested, print serial to stdio
	printf("%s\n", cfg.serialnumber);

	// done
	return 0;
}
