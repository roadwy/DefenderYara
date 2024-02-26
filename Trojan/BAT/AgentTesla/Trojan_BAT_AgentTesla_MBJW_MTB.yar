
rule Trojan_BAT_AgentTesla_MBJW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBJW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 07 5d 13 0b 07 11 06 91 13 0c 11 05 11 0b 6f 90 01 01 00 00 0a 13 0d 07 06 17 58 09 5d 91 13 0e 11 0c 11 0d 61 11 0e 59 20 00 01 00 00 58 13 0f 07 11 06 11 0f 20 00 01 00 00 5d d2 9c 90 00 } //01 00 
		$a_01_1 = {43 6c 75 73 74 65 72 5f 4d 47 46 2e 50 72 6f 70 65 72 } //00 00  Cluster_MGF.Proper
	condition:
		any of ($a_*)
 
}