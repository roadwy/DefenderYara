
rule Trojan_BAT_AgentTesla_EFU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EFU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {df 02 df 02 e0 02 e0 02 0c 03 ef 02 ee 02 df 02 df 02 df 02 e0 02 e7 02 eb 02 e7 02 e2 02 df 02 df 02 df 02 05 03 0b 03 df 02 eb 02 df 02 df 02 e1 02 05 03 e6 02 df 02 df 02 df 02 10 03 e5 02 } //1
		$a_01_1 = {e6 02 02 03 e0 02 e3 02 df 02 df 02 df 02 e3 02 0f 03 e3 02 18 03 df 02 e6 02 df 02 e3 02 e7 02 e0 02 df 02 df 02 df 02 e4 02 df 02 df 02 df 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}