
rule Trojan_BAT_AgentTesla_RDAB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 6f 14 00 00 0a 28 15 00 00 0a 73 16 00 00 0a 0d 09 6f 17 00 00 0a 13 04 11 04 13 05 11 05 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}