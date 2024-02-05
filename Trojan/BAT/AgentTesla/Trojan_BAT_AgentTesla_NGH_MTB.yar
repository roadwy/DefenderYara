
rule Trojan_BAT_AgentTesla_NGH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 16 8d 90 01 03 01 28 90 01 03 0a 73 90 01 03 0a 7a 73 90 01 03 0a 80 90 01 03 04 7e 90 01 03 04 90 00 } //01 00 
		$a_01_1 = {57 00 69 00 6e 00 46 00 6f 00 72 00 6d 00 73 00 5f 00 53 00 65 00 65 00 49 00 6e 00 6e 00 65 00 72 00 45 00 78 00 63 00 65 00 70 00 74 00 69 00 6f 00 6e 00 } //01 00 
		$a_01_2 = {42 65 64 66 6f 72 64 2e 52 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}