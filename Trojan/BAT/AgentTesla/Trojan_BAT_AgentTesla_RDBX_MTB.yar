
rule Trojan_BAT_AgentTesla_RDBX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 1f 16 5d 91 13 07 09 11 06 91 11 07 61 11 06 17 58 11 04 5d 13 08 09 11 08 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}