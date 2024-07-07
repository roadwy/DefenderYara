
rule Trojan_BAT_AgentTesla_UL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.UL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {19 8d 22 00 00 01 25 16 72 e1 01 00 70 a2 25 17 72 f3 01 00 70 a2 25 18 72 8f 01 00 70 a2 0a 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}