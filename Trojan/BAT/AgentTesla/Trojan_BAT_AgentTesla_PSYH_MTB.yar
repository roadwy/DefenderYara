
rule Trojan_BAT_AgentTesla_PSYH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSYH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 6f 5e 00 00 0a 16 6a 6f 5f 00 00 0a 08 08 6f 5e 00 00 0a 6f 65 00 00 0a 69 6f 66 00 00 0a 0d 08 6f 67 00 00 0a 09 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}