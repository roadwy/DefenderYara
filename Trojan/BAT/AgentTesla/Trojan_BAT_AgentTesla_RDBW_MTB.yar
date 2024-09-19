
rule Trojan_BAT_AgentTesla_RDBW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDBW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 1f 16 5d 91 13 04 07 09 91 11 04 61 09 17 58 08 5d 13 05 07 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}