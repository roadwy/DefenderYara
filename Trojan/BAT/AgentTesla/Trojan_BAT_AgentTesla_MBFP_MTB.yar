
rule Trojan_BAT_AgentTesla_MBFP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {6c 00 6d 00 2e 00 6f 00 51 00 } //01 00  lm.oQ
		$a_01_1 = {4c 00 6f 00 61 00 64 00 } //01 00  Load
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00  CreateInstance
	condition:
		any of ($a_*)
 
}