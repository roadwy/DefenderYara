
rule Trojan_BAT_AgentTesla_ABKG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABKG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 06 07 06 9a 1f 10 28 90 01 03 0a 6f 90 01 03 0a 06 17 58 0a 06 07 8e 69 fe 04 13 09 11 09 2d df 90 00 } //4
		$a_01_1 = {50 72 6f 6a 65 63 74 41 49 2e 52 43 53 41 43 44 } //1 ProjectAI.RCSACD
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}