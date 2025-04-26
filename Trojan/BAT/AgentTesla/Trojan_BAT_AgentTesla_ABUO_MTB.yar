
rule Trojan_BAT_AgentTesla_ABUO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABUO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 07 2b 1e 08 07 11 07 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a b4 6f ?? 00 00 0a 00 11 07 18 d6 13 07 11 07 11 06 31 dc } //3
		$a_01_1 = {61 00 70 00 70 00 50 00 69 00 7a 00 7a 00 61 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 appPizza.Resources
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}