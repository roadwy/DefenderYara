
rule Trojan_BAT_Marsilia_AMR_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.AMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 13 09 2b 20 11 08 11 09 9a 13 0a 00 00 00 de 0d 26 00 11 0a 6f 90 01 01 00 00 0a 00 00 de 00 00 11 09 17 58 13 09 11 09 11 08 8e 69 32 d8 90 00 } //01 00 
		$a_01_1 = {48 00 79 00 70 00 69 00 78 00 65 00 6c 00 53 00 6b 00 79 00 62 00 6c 00 6f 00 63 00 6b 00 44 00 75 00 70 00 65 00 2e 00 65 00 78 00 65 00 } //00 00  HypixelSkyblockDupe.exe
	condition:
		any of ($a_*)
 
}