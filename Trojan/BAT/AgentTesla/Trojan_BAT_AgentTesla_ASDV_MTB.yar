
rule Trojan_BAT_AgentTesla_ASDV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 0f 17 8d 90 01 01 00 00 01 25 16 11 05 11 0f 9a 1f 10 28 90 01 01 00 00 0a b4 9c 6f 90 01 01 00 00 0a 00 11 0f 17 d6 13 0f 11 0f 11 0e 31 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}