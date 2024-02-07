
rule Trojan_BAT_AgentTesla_LVD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 48 11 04 06 07 28 90 01 03 06 13 06 11 05 20 90 01 03 6a 28 90 01 03 06 20 90 01 03 00 14 14 17 8d 90 01 03 01 25 16 11 06 8c 90 01 03 01 a2 6f 90 01 03 0a a5 90 01 03 01 13 07 09 08 11 07 28 90 01 03 0a 9c 07 17 58 0b 07 17 fe 04 13 08 11 08 2d ae 08 90 00 } //01 00 
		$a_01_1 = {47 65 74 50 69 78 65 6c } //00 00  GetPixel
	condition:
		any of ($a_*)
 
}