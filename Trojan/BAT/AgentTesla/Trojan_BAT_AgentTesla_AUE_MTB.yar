
rule Trojan_BAT_AgentTesla_AUE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AUE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {11 04 06 16 06 8e 69 6f 90 01 03 0a 0b 07 2c 09 09 06 16 07 6f 90 01 03 0a 07 06 8e 69 2e 90 00 } //01 00 
		$a_80_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  01 00 
		$a_80_2 = {47 65 74 54 79 70 65 73 } //GetTypes  01 00 
		$a_80_3 = {47 65 74 4d 65 74 68 6f 64 73 } //GetMethods  00 00 
	condition:
		any of ($a_*)
 
}