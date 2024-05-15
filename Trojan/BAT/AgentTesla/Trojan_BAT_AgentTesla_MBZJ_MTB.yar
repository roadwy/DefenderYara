
rule Trojan_BAT_AgentTesla_MBZJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBZJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {8e 69 6a 5d d4 91 08 11 90 01 01 69 90 00 } //05 00 
		$a_81_1 = {4c 6f 21 21 21 21 21 61 64 } //01 00  Lo!!!!!ad
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_3 = {53 70 6c 69 74 } //00 00  Split
	condition:
		any of ($a_*)
 
}