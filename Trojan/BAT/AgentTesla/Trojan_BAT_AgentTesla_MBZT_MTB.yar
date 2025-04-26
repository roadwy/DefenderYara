
rule Trojan_BAT_AgentTesla_MBZT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 58 07 8e 69 5d 91 13 [0-20] 61 13 [0-20] 59 20 00 01 00 00 58 20 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}