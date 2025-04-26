
rule TrojanDropper_BAT_Marsilia_NIT_MTB{
	meta:
		description = "TrojanDropper:BAT/Marsilia.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 6f 1c 00 00 0a 73 19 00 00 0a 13 06 1a 8d 1a 00 00 01 13 07 11 06 11 07 16 1a 6f ?? 00 00 0a 26 11 07 16 28 ?? 00 00 0a 13 08 11 06 16 73 1f 00 00 0a 13 09 11 09 11 05 6f ?? 00 00 0a 73 20 00 00 0a 13 0a 11 0a 11 05 6f ?? 00 00 0a 6f ?? 00 00 0a 11 0a 13 0a dd 63 00 00 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule TrojanDropper_BAT_Marsilia_NIT_MTB_2{
	meta:
		description = "TrojanDropper:BAT/Marsilia.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 6d 62 65 64 64 65 64 42 61 74 63 68 53 63 72 69 70 74 } //1 embeddedBatchScript
		$a_01_1 = {54 45 4d 50 5c 62 32 61 2e 63 } //1 TEMP\b2a.c
		$a_01_2 = {28 05 00 00 0a 1b 8d 0a 00 00 01 13 04 11 04 16 72 27 00 00 70 a2 11 04 17 7e 01 00 00 04 a2 11 04 18 72 31 00 00 70 a2 11 04 19 7e 02 00 00 04 a2 11 04 1a 72 35 00 00 70 a2 11 04 28 06 00 00 0a 28 07 00 00 0a 0a 06 28 08 00 00 0a 2c 11 06 20 80 00 00 00 28 09 00 00 0a 06 28 0a 00 00 0a 06 72 3f 00 00 70 28 04 00 00 06 28 05 00 00 06 28 0b 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}