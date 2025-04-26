
rule Trojan_BAT_AgentTesla_RDBV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 6f 75 00 00 0a 16 9a 0c 08 6f 76 00 00 0a 17 9a 0d 11 07 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}