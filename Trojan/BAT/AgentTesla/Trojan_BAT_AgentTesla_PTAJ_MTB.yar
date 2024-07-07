
rule Trojan_BAT_AgentTesla_PTAJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {38 d2 d6 ff ff 28 90 01 01 00 00 06 25 17 28 90 01 01 00 00 06 11 09 11 0b 28 90 01 01 00 00 06 13 04 20 0e 00 00 00 28 90 01 01 00 00 06 39 ac d6 ff ff 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}