
rule Trojan_BAT_AgentTesla_PSVV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSVV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 63 72 0d 00 00 70 38 5f 00 00 00 1a 2d 1a 26 38 60 00 00 00 1b 2d 15 26 16 2d e4 38 5e 00 00 00 8e 69 17 2d 0e } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}