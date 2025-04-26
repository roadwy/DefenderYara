
rule Trojan_BAT_AgentTesla_BAL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {26 38 00 00 00 00 20 88 13 00 00 28 ?? 00 00 0a 38 00 00 00 00 dd ?? 00 00 00 38 00 00 00 00 11 02 17 58 13 02 38 } //1
		$a_01_1 = {62 00 6c 00 6c 00 31 00 30 00 2e 00 73 00 68 00 6f 00 70 00 2f 00 67 00 70 00 41 00 49 00 48 00 42 00 49 00 54 00 } //1 bll10.shop/gpAIHBIT
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}