
rule Trojan_BAT_AgentTesla_SF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {11 04 18 6f 90 01 03 0a 90 01 05 28 90 01 03 0a 04 07 6f 90 01 03 0a 90 01 05 6a 61 b7 28 90 01 03 0a 28 90 01 03 0a 13 05 08 11 05 6f 90 01 03 0a 26 07 04 90 01 05 17 da 33 90 00 } //01 00 
		$a_80_1 = {58 4f 52 5f 44 65 63 72 79 70 74 } //XOR_Decrypt  01 00 
		$a_80_2 = {73 61 64 61 64 61 } //sadada  00 00 
	condition:
		any of ($a_*)
 
}