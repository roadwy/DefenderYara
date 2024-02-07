
rule Trojan_BAT_AgentTesla_MBCG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 36 66 63 37 30 61 62 61 2d 31 32 66 31 2d 34 66 38 32 2d 39 32 32 36 2d 62 63 33 34 35 31 36 30 36 62 31 33 } //01 00  $6fc70aba-12f1-4f82-9226-bc3451606b13
		$a_01_1 = {50 69 6e 74 65 72 65 73 74 5f 42 6f 61 72 64 5f 4d 61 6e 61 67 65 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //00 00  Pinterest_Board_Manager.Resources.resource
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_MBCG_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {34 00 44 00 5a 00 35 00 41 00 5a 00 39 00 30 00 40 00 30 00 40 00 33 00 40 00 30 00 40 00 30 00 40 00 30 00 40 00 34 00 40 00 30 00 40 00 30 00 40 00 30 00 5a 00 46 00 46 00 5a 00 46 00 46 00 40 00 30 00 40 00 } //01 00  4DZ5AZ90@0@3@0@0@0@4@0@0@0ZFFZFF@0@
		$a_01_1 = {30 00 40 00 30 00 40 00 32 00 5a 00 32 00 31 00 40 00 42 00 40 00 31 00 40 00 38 00 40 00 30 00 40 00 30 00 5a 00 35 00 34 00 } //00 00  0@0@2Z21@B@1@8@0@0Z54
	condition:
		any of ($a_*)
 
}