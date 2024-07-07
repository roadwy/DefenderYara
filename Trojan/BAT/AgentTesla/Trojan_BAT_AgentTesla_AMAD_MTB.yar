
rule Trojan_BAT_AgentTesla_AMAD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 06 07 8e 69 5d 07 11 06 07 8e 69 5d 91 08 11 06 08 6f 90 01 01 00 00 0a 5d 6f 90 01 01 00 00 0a 61 28 90 01 01 00 00 0a 07 11 06 17 58 07 8e 69 5d 91 28 90 01 01 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 90 01 01 00 00 0a 9c 11 06 15 58 13 06 11 06 16 2f af 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}