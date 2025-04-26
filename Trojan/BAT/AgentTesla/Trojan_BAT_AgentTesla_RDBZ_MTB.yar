
rule Trojan_BAT_AgentTesla_RDBZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {91 13 08 07 09 91 11 08 61 13 09 09 18 58 17 59 08 5d 13 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}