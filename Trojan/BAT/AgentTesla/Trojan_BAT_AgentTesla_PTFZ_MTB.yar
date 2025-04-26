
rule Trojan_BAT_AgentTesla_PTFZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTFZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 01 00 00 70 6f 15 00 00 0a 0d 09 17 8d 1a 00 00 01 25 16 1f 0a 9d 6f 16 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}