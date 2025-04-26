
rule Trojan_BAT_AgentTesla_MBXK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBXK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 58 08 5d [0-12] 59 20 00 01 00 00 58 20 ff 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}