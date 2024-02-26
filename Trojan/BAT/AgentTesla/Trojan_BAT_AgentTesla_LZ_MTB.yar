
rule Trojan_BAT_AgentTesla_LZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {57 df b6 fd 09 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 f8 00 00 00 94 00 00 00 34 04 00 00 f8 14 } //01 00 
		$a_01_1 = {47 65 74 44 6f 6d 61 69 6e } //00 00  GetDomain
	condition:
		any of ($a_*)
 
}