
rule Trojan_BAT_AgentTesla_ABDU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABDU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 06 11 08 9a 1f 10 28 90 01 03 0a 6f 90 01 03 0a 00 11 08 17 58 13 08 11 08 06 8e 69 fe 04 13 09 11 09 2d db 07 6f 90 01 03 0a 0c 90 00 } //4
		$a_01_1 = {50 00 72 00 69 00 73 00 6f 00 6e 00 65 00 72 00 4d 00 61 00 6e 00 61 00 67 00 65 00 6d 00 65 00 6e 00 74 00 53 00 79 00 73 00 74 00 65 00 6d 00 5f 00 2e 00 55 00 49 00 48 00 4f 00 4a 00 44 00 53 00 } //1 PrisonerManagementSystem_.UIHOJDS
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}