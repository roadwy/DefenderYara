
rule Trojan_BAT_AgentTesla_NLN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NLN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 6f 26 00 00 0a 09 16 09 8e 69 6f ?? 00 00 0a 13 04 de 38 07 2b be 28 ?? 00 00 0a 2b b9 6f ?? 00 00 0a 2b b9 } //5
		$a_01_1 = {52 6b 69 6b 63 2e 50 72 6f 70 65 72 74 69 65 73 } //1 Rkikc.Properties
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}