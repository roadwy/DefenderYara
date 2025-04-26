
rule Trojan_BAT_Remcos_SD_MTB{
	meta:
		description = "Trojan:BAT/Remcos.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 20 00 00 0a 0d 02 6f 21 00 00 0a 0b 03 6f 21 00 00 0a 13 04 73 22 00 00 0a 0c 08 28 23 00 00 0a 03 6f 24 00 00 0a 6f 25 00 00 0a 13 06 16 13 05 16 02 6f 26 00 00 0a 17 da 13 0a 13 08 2b 49 02 11 08 18 6f 27 00 00 0a 1f 10 28 28 00 00 0a 11 06 11 05 91 61 28 29 00 00 0a 13 09 09 11 09 6f 2a 00 00 0a 26 11 05 03 6f 26 00 00 0a 17 da fe 01 13 07 11 07 2c 05 16 13 05 2b 06 11 05 17 d6 13 05 11 08 18 d6 13 08 11 08 11 0a 31 b1 09 6f 2b 00 00 0a 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}