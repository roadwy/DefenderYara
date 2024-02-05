
rule Trojan_BAT_AgentTesla_AYL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AYL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {25 16 03 a2 6f 90 01 03 0a 90 01 05 0b 0e 05 90 01 0a 6f 90 01 03 0a 90 01 0a 6f 90 01 03 0a 10 05 07 0e 05 6f 90 01 03 0a 0c 08 0e 04 20 00 01 00 00 14 14 19 90 01 05 25 16 28 90 01 03 06 a2 25 17 28 90 01 03 06 a2 25 18 90 00 } //01 00 
		$a_80_1 = {47 65 74 54 79 70 65 } //GetType  01 00 
		$a_80_2 = {47 65 74 50 69 78 65 6c } //GetPixel  01 00 
		$a_80_3 = {54 6f 57 69 6e 33 32 } //ToWin32  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_AYL_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AYL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {70 0c 07 28 90 01 03 0a 03 6f 90 01 03 0a 6f 90 01 03 0a 0d 06 09 6f 90 01 03 0a 00 06 18 6f 90 01 03 0a 00 02 28 90 01 03 0a 13 04 28 90 01 03 0a 06 6f 90 01 03 0a 11 04 16 11 04 8e 69 6f 90 01 03 0a 6f 90 01 03 0a 0c 08 13 05 2b 90 00 } //01 00 
		$a_80_1 = {47 65 74 4d 65 74 68 6f 64 } //GetMethod  01 00 
		$a_80_2 = {47 65 74 54 79 70 65 } //GetType  01 00 
		$a_80_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //TransformFinalBlock  00 00 
	condition:
		any of ($a_*)
 
}