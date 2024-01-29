#include "telnet.h"

void TelnetClient_init(struct TelnetClient* cli)
{
	cli->host = NULL;
	cli->port = NULL;
	cli->user = NULL;
	cli->pass = NULL;
	cli->connected = 0;
	cli->loggedIn = 0;
	cli->sock = INVALID_SOCKET;
	/*cli->__buf_sz__ = 0;
	cli->__buf_edge__ = NULL;
	cli->__buf__ = NULL;
	cli->__pos__ = NULL;*/
}

int __TelnetClient_readNextRaw__(struct TelnetClient* cli)
{
	unsigned char c;
	ssize_t ret = recv(cli->sock, &c, sizeof(unsigned char), 0);
	if(ret != sizeof(c))
	{
		cli->connected = 0;
		return -1;
	}
	return c;
}

/*int __TelnetClient_readBufferedChar__(struct TelnetClient* cli)
{
	if(cli->__pos__ < (cli->__buf__ + cli->__buf_sz__))
		return *(cli->__pos__++);
}*/

int __TelnetClient_readNext_(struct TelnetClient* cli)
{
	int c;
	while(1)
	{
		c = __TelnetClient_readNextRaw__(cli);
		if(c < 0) return c;
		if(c == 255)
		{
			c = __TelnetClient_readNextRaw__(cli);
			if(c < 0) return c;
			switch(c)
			{
				case 240:	// Suboption end
							break;
				case 250:	// Suboption
							while(1)
							{
								c = __TelnetClient_readNextRaw__(cli);
								if(c < 0) return c;
								if(c != 0xff)
									break;
							}
							c = __TelnetClient_readNextRaw__(cli); // discard the 0xf0 byte
							if(c < 0) return c;
							break;
				case 251:	// Will
							c = __TelnetClient_readNextRaw__(cli);
							if(c < 0) return c;
							printf("[rx: WILL %02x]\n", c);
							break;
				case 253:	// Do
							c = __TelnetClient_readNextRaw__(cli);
							if(c < 0) return c;
							printf("[rx: DO %02x]\n", c);
							switch(c)
							{
								case 0x01:	// Will Echo
											// send 0xff 0xfb c
								case 0x18:	// Will Terminal Type
								case 0x1f:	// Will Negotiate About Window Size
								case 0x20:	// Wont Terminal Speed
								case 0x23:	// Wont X Display Location
								case 0x24:	// Wont Environment Option
								default:	// Wont do anything else
										{
											char res[] = { 0xff, 0xfc, (char)c };
											send(cli->sock, res, 3, 0);
											printf("[tx: WONT %02x]\n", c);
										}
							}
							break;
				case 255:	// A literal 255 byte
							return 255;
				default:	printf("[rx: unknown command %d]\n", c);
			}
		}
		else
			return c;
	}
}