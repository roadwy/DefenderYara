
rule Trojan_BAT_Marsilia_AMR_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.AMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 1f 10 0b 07 28 ?? 00 00 06 68 0c 08 20 00 80 00 00 5f 20 00 80 00 00 fe 01 13 05 11 05 2c 04 00 17 0a 00 28 ?? 00 00 0a 0d 06 09 60 13 04 11 04 13 06 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Marsilia_AMR_MTB_2{
	meta:
		description = "Trojan:BAT/Marsilia.AMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 08 2b 3b 11 07 11 08 9a 13 09 11 05 11 09 6f ?? 00 00 0a 13 0a 12 0a 28 ?? 00 00 0a 58 13 05 11 06 11 09 6f ?? 00 00 0a 13 0a 12 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 13 06 11 08 17 58 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_Marsilia_AMR_MTB_3{
	meta:
		description = "Trojan:BAT/Marsilia.AMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 00 02 0b 16 0c 2b 1a 07 08 91 0d 06 72 70 0a 00 70 09 8c 6f 00 00 01 6f ?? 00 00 0a 26 08 17 58 0c 08 07 8e 69 } //2
		$a_01_1 = {74 65 73 74 5f 61 69 6d 62 6f 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 test_aimbot.Properties.Resources
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_Marsilia_AMR_MTB_4{
	meta:
		description = "Trojan:BAT/Marsilia.AMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 09 2b 20 11 08 11 09 9a 13 0a 00 00 00 de 0d 26 00 11 0a 6f ?? 00 00 0a 00 00 de 00 00 11 09 17 58 13 09 11 09 11 08 8e 69 32 d8 } //2
		$a_01_1 = {48 00 79 00 70 00 69 00 78 00 65 00 6c 00 53 00 6b 00 79 00 62 00 6c 00 6f 00 63 00 6b 00 44 00 75 00 70 00 65 00 2e 00 65 00 78 00 65 00 } //1 HypixelSkyblockDupe.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}