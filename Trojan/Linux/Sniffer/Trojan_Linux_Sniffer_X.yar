
rule Trojan_Linux_Sniffer_X{
	meta:
		description = "Trojan:Linux/Sniffer.X,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {2f 62 69 6e 2f 73 68 } ///bin/sh  01 00 
		$a_80_1 = {70 63 61 70 5f 73 65 74 66 69 6c 74 65 72 } //pcap_setfilter  01 00 
		$a_80_2 = {70 63 61 70 5f 6f 70 65 6e 5f 6c 69 76 65 } //pcap_open_live  01 00 
		$a_80_3 = {6c 69 62 70 63 61 70 2e 73 6f } //libpcap.so  01 00 
		$a_03_4 = {49 89 c8 41 0f b6 14 90 01 01 41 83 e0 03 42 32 14 03 80 ea 65 74 09 83 c0 01 88 14 37 48 63 f0 48 83 c1 01 48 83 f9 40 75 d8 90 00 } //01 00 
		$a_01_5 = {41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 30 31 32 33 34 35 36 37 38 39 2b 2f } //00 00  ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
	condition:
		any of ($a_*)
 
}