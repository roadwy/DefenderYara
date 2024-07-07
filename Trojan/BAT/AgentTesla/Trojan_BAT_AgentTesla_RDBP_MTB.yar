
rule Trojan_BAT_AgentTesla_RDBP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {6e 11 0c 20 ff 00 00 00 5f 6a 61 d2 9c 11 09 17 6a 58 13 09 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}