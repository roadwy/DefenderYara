
rule Trojan_BAT_AgentTesla_KAAO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KAAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 08 06 08 91 72 90 01 01 00 00 70 28 90 01 01 00 00 0a 59 d2 9c 08 17 58 0c 08 06 8e 69 32 e4 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}