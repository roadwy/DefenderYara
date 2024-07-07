
rule Trojan_BAT_AgentTesla_NEI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 0a 16 9a 72 90 01 01 05 00 70 18 17 8d 90 01 01 00 00 01 25 16 02 a2 28 90 01 01 00 00 0a 0a 2b 00 06 2a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}