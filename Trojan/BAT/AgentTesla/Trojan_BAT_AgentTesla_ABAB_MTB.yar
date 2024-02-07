
rule Trojan_BAT_AgentTesla_ABAB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 04 00 "
		
	strings :
		$a_03_0 = {07 08 09 28 90 01 03 06 28 90 01 03 06 28 90 01 03 06 28 90 01 03 06 28 90 01 03 06 7e 90 01 03 04 06 28 90 01 03 06 d2 9c 09 17 58 0d 09 17 fe 04 13 04 11 04 2d c9 06 17 58 0a 08 17 58 0c 08 20 90 01 03 00 fe 04 13 05 11 05 2d af 90 00 } //01 00 
		$a_01_1 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_01_2 = {47 65 74 42 79 74 65 73 } //00 00  GetBytes
	condition:
		any of ($a_*)
 
}