
rule Trojan_BAT_Marsilia_AMR_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.AMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 1f 10 0b 07 28 90 01 01 00 00 06 68 0c 08 20 00 80 00 00 5f 20 00 80 00 00 fe 01 13 05 11 05 2c 04 00 17 0a 00 28 90 01 01 00 00 0a 0d 06 09 60 13 04 11 04 13 06 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Marsilia_AMR_MTB_2{
	meta:
		description = "Trojan:BAT/Marsilia.AMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 09 2b 20 11 08 11 09 9a 13 0a 00 00 00 de 0d 26 00 11 0a 6f 90 01 01 00 00 0a 00 00 de 00 00 11 09 17 58 13 09 11 09 11 08 8e 69 32 d8 90 00 } //2
		$a_01_1 = {48 00 79 00 70 00 69 00 78 00 65 00 6c 00 53 00 6b 00 79 00 62 00 6c 00 6f 00 63 00 6b 00 44 00 75 00 70 00 65 00 2e 00 65 00 78 00 65 00 } //1 HypixelSkyblockDupe.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}