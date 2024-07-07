
rule Trojan_BAT_AgentTesla_PTKI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 08 02 16 02 8e 69 6f 82 00 00 0a 00 11 08 6f 83 00 00 0a 00 11 07 6f 84 00 00 0a 0c de 0e } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}