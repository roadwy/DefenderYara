
rule HackTool_Linux_SolSniffer_A{
	meta:
		description = "HackTool:Linux/SolSniffer.A,SIGNATURE_TYPE_ELFHSTR_EXT,23 00 23 00 07 00 00 05 00 "
		
	strings :
		$a_80_0 = {2d 2d 20 54 43 50 2f 49 50 20 4c 4f 47 20 2d 2d 20 54 4d 3a 20 25 73 20 2d 2d } //-- TCP/IP LOG -- TM: %s --  05 00 
		$a_80_1 = {53 54 41 54 3a 20 25 73 2c 20 25 64 20 70 6b 74 73 2c 20 25 64 20 62 79 74 65 73 20 5b 25 73 5d } //STAT: %s, %d pkts, %d bytes [%s]  05 00 
		$a_80_2 = {55 73 61 67 65 3a 20 25 73 20 5b 2d 64 20 78 5d 20 5b 2d 73 5d 20 5b 2d 66 5d 20 5b 2d 6c 5d 20 5b 2d 74 5d 20 5b 2d 69 20 69 6e 74 65 72 66 61 63 65 5d 20 5b 2d 6f 20 66 69 6c 65 5d } //Usage: %s [-d x] [-s] [-f] [-l] [-t] [-i interface] [-o file]  05 00 
		$a_80_3 = {44 4c 5f 50 52 4f 4d 49 53 43 5f 50 48 59 53 } //DL_PROMISC_PHYS  05 00 
		$a_80_4 = {64 6c 62 69 6e 64 61 63 6b 3a 20 20 44 4c 5f 4f 4b 5f 41 43 4b 20 77 61 73 20 6e 6f 74 20 4d 5f 50 43 50 52 4f 54 4f } //dlbindack:  DL_OK_ACK was not M_PCPROTO  05 00 
		$a_80_5 = {66 69 6c 74 65 72 69 6e 67 20 6f 75 74 20 74 65 6c 6e 65 74 20 63 6f 6e 6e 65 63 74 69 6f 6e 73 2e } //filtering out telnet connections.  05 00 
		$a_80_6 = {66 69 6c 74 65 72 69 6e 67 20 6f 75 74 20 72 73 68 2f 72 6c 6f 67 69 6e 20 63 6f 6e 6e 65 63 74 69 6f 6e 73 2e } //filtering out rsh/rlogin connections.  00 00 
	condition:
		any of ($a_*)
 
}