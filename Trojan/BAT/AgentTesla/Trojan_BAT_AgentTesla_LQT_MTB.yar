
rule Trojan_BAT_AgentTesla_LQT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LQT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0b 2b 1f 02 11 04 06 07 28 90 01 03 06 28 90 01 03 0a 13 05 09 08 11 05 28 90 01 03 0a 9c 07 17 58 0b 07 17 32 dd 90 00 } //0a 00 
		$a_03_1 = {16 13 04 2b 27 00 02 08 09 11 04 28 90 01 03 06 13 05 11 05 28 90 01 03 0a 13 06 07 06 11 06 28 90 01 03 0a 9c 00 11 04 17 58 13 04 11 04 17 fe 04 13 07 11 07 2d ce 90 00 } //01 00 
		$a_01_2 = {47 65 74 50 69 78 65 6c } //00 00 
	condition:
		any of ($a_*)
 
}