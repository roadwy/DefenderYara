
rule Trojan_BAT_AgentTesla_LK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {16 9a 18 3a 90 01 04 26 38 90 01 03 00 11 01 02 28 90 01 04 6f 90 01 04 11 00 11 01 6f 90 01 04 6f 90 01 04 1e 3a 90 01 03 00 26 11 02 17 8d 90 01 04 25 16 02 28 90 00 } //01 00 
		$a_80_1 = {43 6c 61 73 73 4c 69 62 72 61 72 79 31 } //ClassLibrary1  01 00 
		$a_80_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  00 00 
	condition:
		any of ($a_*)
 
}