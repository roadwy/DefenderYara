
rule Trojan_BAT_AgentTesla_ANMO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ANMO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 16 72 90 01 03 70 a2 11 04 17 7e 90 01 03 0a a2 11 04 18 06 a2 11 04 0c 07 28 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}