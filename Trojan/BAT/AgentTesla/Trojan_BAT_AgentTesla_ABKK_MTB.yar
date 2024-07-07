
rule Trojan_BAT_AgentTesla_ABKK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 06 07 06 9a 1f 10 28 90 01 03 0a 6f 90 01 03 0a 06 17 58 0a 06 07 8e 69 fe 04 13 09 11 09 2d df 90 00 } //4
		$a_01_1 = {47 61 6d 65 32 30 34 38 46 6f 72 6d 2e 53 46 44 44 57 45 44 2e 72 65 73 6f 75 72 63 65 73 } //1 Game2048Form.SFDDWED.resources
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}