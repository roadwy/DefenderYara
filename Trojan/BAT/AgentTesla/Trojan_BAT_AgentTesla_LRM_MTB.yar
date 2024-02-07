
rule Trojan_BAT_AgentTesla_LRM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LRM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 05 2b 4e 00 09 11 04 11 05 28 90 01 03 06 13 07 11 06 72 90 01 03 70 28 90 01 03 0a 20 90 01 03 00 14 14 17 8d 90 01 03 01 25 16 11 07 8c 90 01 03 01 a2 6f 90 01 03 0a a5 90 01 03 01 13 08 17 13 09 00 08 07 11 08 d2 9c 00 00 11 05 17 58 13 05 11 05 17 fe 04 13 0a 11 0a 2d a7 90 00 } //01 00 
		$a_01_1 = {47 65 74 50 69 78 65 6c } //00 00  GetPixel
	condition:
		any of ($a_*)
 
}