
rule Trojan_BAT_AgentTesla_DAZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {11 08 11 05 11 01 11 05 9a 1f 10 28 90 01 01 00 00 0a d2 9c 20 26 00 00 00 38 90 01 02 ff ff 00 02 7b 90 01 01 00 00 04 16 6f 90 01 01 00 00 0a 38 90 01 02 ff ff 00 02 7b 90 01 01 00 00 04 02 90 00 } //01 00 
		$a_01_1 = {53 70 6c 69 74 } //00 00  Split
	condition:
		any of ($a_*)
 
}