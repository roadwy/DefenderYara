
rule Trojan_BAT_AgentTesla_RDBI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 09 5d 13 0f 08 07 91 11 0e 61 08 11 0f 91 59 13 10 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}