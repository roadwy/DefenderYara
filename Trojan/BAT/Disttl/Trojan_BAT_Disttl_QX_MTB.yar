
rule Trojan_BAT_Disttl_QX_MTB{
	meta:
		description = "Trojan:BAT/Disttl.QX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {15 0a 28 04 00 00 0a 02 6f 05 00 00 0a 0b 07 13 04 16 13 05 2b 40 11 04 11 05 91 0c 06 08 1f 18 62 61 0a 16 0d 2b 25 06 6a 20 00 00 00 80 6e 5f 20 00 00 00 80 6e 33 0c 06 17 62 20 b7 1d c1 04 61 0a 2b 04 06 17 62 0a 09 17 58 0d 09 1e 32 d7 11 05 17 58 13 05 11 05 11 04 8e 69 32 b8 06 2a } //1
		$a_00_1 = {0b 02 03 61 0c 08 1f 11 5a 1f 1b 5b 0c 07 1d 08 58 6a 16 6f 08 00 00 0a 26 1e 8d 07 00 00 01 0d 07 09 16 1a 6f 09 00 00 0a 26 09 16 28 0a 00 00 0a 20 68 dc 2d 7d 61 1f 64 59 13 04 07 09 16 1a 6f 09 00 00 0a 26 09 16 28 0a 00 00 0a 1b 59 20 2f 6a f2 1c 61 13 05 07 11 04 6a 16 6f 08 00 00 0a 26 11 05 8d 07 00 00 01 0d 07 09 16 11 05 6f 09 00 00 0a } //1
		$a_01_2 = {44 00 69 00 73 00 63 00 6f 00 72 00 64 00 } //1 Discord
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}