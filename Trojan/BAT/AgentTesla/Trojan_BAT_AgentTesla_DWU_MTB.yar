
rule Trojan_BAT_AgentTesla_DWU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DWU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {16 13 05 2b 2a 00 09 11 04 11 05 28 90 01 03 06 13 08 11 08 28 90 01 03 06 13 09 17 13 0a 08 11 09 d2 6f 90 01 03 0a 00 00 11 05 17 58 13 05 11 05 17 fe 04 13 0b 11 0b 2d cb 90 00 } //0a 00 
		$a_03_1 = {16 13 05 2b 2a 00 09 11 04 11 05 28 90 01 03 06 13 08 11 08 28 90 01 03 0a 13 09 17 13 0a 08 11 09 d2 6f 90 01 03 0a 00 00 11 05 17 58 13 05 11 05 17 fe 04 13 0b 11 0b 2d cb 07 17 58 0b 00 11 04 17 58 13 04 90 00 } //01 00 
		$a_81_2 = {54 6f 57 69 6e 33 32 } //01 00  ToWin32
		$a_81_3 = {47 65 74 50 69 78 65 6c } //00 00  GetPixel
	condition:
		any of ($a_*)
 
}