
rule Trojan_BAT_Marsilia_SXXP_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.SXXP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {0b 02 72 17 00 00 70 72 1b 00 00 70 6f 90 01 03 0a 28 90 01 03 0a 0c 28 90 01 03 0a 07 08 16 08 8e 69 6f 90 01 03 0a 6f 90 01 03 0a 0d 2b 00 90 00 } //01 00 
		$a_01_1 = {48 79 70 69 78 65 6c 53 6b 79 62 6c 6f 63 6b 44 75 70 65 } //00 00  HypixelSkyblockDupe
	condition:
		any of ($a_*)
 
}