
rule Trojan_BAT_AgentTesla_ABKW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABKW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 06 07 06 9a 1f 10 28 90 01 03 0a 6f 90 01 03 0a 06 17 58 0a 06 07 8e 69 fe 04 13 08 11 08 2d df 90 00 } //5
		$a_01_1 = {46 72 61 6d 65 77 6f 72 6b 45 6e 74 69 74 79 2e 4d 4e 42 56 42 2e 72 65 73 6f 75 72 63 65 73 } //1 FrameworkEntity.MNBVB.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}