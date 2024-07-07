
rule Trojan_BAT_AgentTesla_MBZY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 91 61 07 11 90 02 04 8e 69 5d 91 59 20 00 01 00 00 58 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}