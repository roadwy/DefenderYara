
rule Trojan_BAT_AgentTesla_AYM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AYM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {25 16 03 a2 25 0d 14 14 17 8d 90 01 03 01 25 16 17 9c 25 13 04 28 90 01 03 0a 11 04 16 91 2c 03 17 2b 03 16 2b 00 2d 02 2b 0c 09 16 9a 90 00 } //01 00 
		$a_80_1 = {54 6f 57 69 6e 33 32 } //ToWin32  01 00 
		$a_80_2 = {47 65 74 54 79 70 65 } //GetType  01 00 
		$a_80_3 = {53 65 6c 65 63 74 6f 72 58 } //SelectorX  00 00 
	condition:
		any of ($a_*)
 
}