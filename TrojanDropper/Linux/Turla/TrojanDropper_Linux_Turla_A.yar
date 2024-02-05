
rule TrojanDropper_Linux_Turla_A{
	meta:
		description = "TrojanDropper:Linux/Turla.A,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {63 72 6f 6e } //cron  01 00 
		$a_80_1 = {2f 62 69 6e 2f 73 68 } ///bin/sh  01 00 
		$a_80_2 = {70 63 61 70 5f 73 65 74 66 69 6c 74 65 72 } //pcap_setfilter  01 00 
		$a_80_3 = {70 63 61 70 5f 6f 70 65 6e 5f 6c 69 76 65 } //pcap_open_live  01 00 
		$a_80_4 = {6c 69 62 70 63 61 70 2e 73 6f } //libpcap.so  01 00 
		$a_03_5 = {49 89 c8 41 0f b6 14 90 01 01 41 83 e0 03 42 32 14 03 80 ea 65 74 09 83 c0 01 88 14 37 48 63 f0 48 83 c1 01 48 83 f9 40 75 d8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}