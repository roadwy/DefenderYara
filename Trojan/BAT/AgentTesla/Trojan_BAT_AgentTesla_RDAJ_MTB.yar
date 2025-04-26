
rule Trojan_BAT_AgentTesla_RDAJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 16 02 8e 69 6f 0f 00 00 0a 0b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}