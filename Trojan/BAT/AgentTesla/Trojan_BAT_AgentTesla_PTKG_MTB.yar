
rule Trojan_BAT_AgentTesla_PTKG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTKG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 08 8e 69 28 90 01 01 00 00 0a 07 16 11 04 07 8e 69 28 90 01 01 00 00 0a 09 11 04 28 90 01 01 00 00 06 6f 11 00 00 0a 2a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}