
rule Trojan_BAT_AgentTesla_ETF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ETF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {17 da 17 d6 02 11 06 91 08 1f 0a d6 1f 0a da 61 07 90 01 05 11 07 91 61 b4 9c 90 00 } //01 00 
		$a_01_1 = {02 02 8e 69 17 da 91 1f 70 61 0c } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_ETF_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ETF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {17 da 17 d6 02 11 06 91 08 1f 0a d6 1f 0a da 61 07 74 90 01 03 1b 11 07 91 61 b4 9c 1d 90 00 } //01 00 
		$a_01_1 = {02 02 8e 69 17 da 91 1f 70 61 0c 19 } //00 00 
	condition:
		any of ($a_*)
 
}