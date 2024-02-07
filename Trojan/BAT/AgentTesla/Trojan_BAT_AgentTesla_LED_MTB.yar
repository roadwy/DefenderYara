
rule Trojan_BAT_AgentTesla_LED_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 06 07 6f 90 01 03 0a 26 08 06 07 6f 90 01 03 0a 13 05 11 05 28 90 01 03 0a 13 06 11 04 09 11 06 d2 9c 07 17 58 0b 07 08 6f 90 01 03 0a 13 08 12 08 28 90 01 03 0a fe 04 13 07 11 07 2d 90 00 } //01 00 
		$a_01_1 = {54 6f 57 69 6e 33 32 } //01 00  ToWin32
		$a_80_2 = {47 65 74 50 69 78 65 6c } //GetPixel  00 00 
	condition:
		any of ($a_*)
 
}