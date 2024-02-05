
rule Trojan_BAT_AgentTesla_EKM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 8e 69 17 da 17 d6 8d 90 01 03 01 0c 08 07 08 16 02 8e 69 6f 90 01 03 0a 28 90 01 03 2b 28 90 01 03 2b 0a de 0c 90 00 } //01 00 
		$a_01_1 = {0a ca ed b8 28 26 11 22 5b 70 2a 48 7e f2 e0 43 a3 08 54 d1 ed 9f b6 1c 21 de 51 bb 79 79 dd fb 1b e4 96 fb bd da 02 cf 8c e5 a5 82 c2 75 23 bf } //00 00 
	condition:
		any of ($a_*)
 
}