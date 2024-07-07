
rule Trojan_BAT_AgentTesla_ENG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ENG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 04 20 00 38 01 00 5d 07 11 04 20 00 38 01 00 5d 91 08 11 04 1f 16 5d 6f 90 01 03 0a 61 28 90 01 03 0a 07 11 04 17 58 20 00 38 01 00 5d 91 28 90 01 03 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 90 01 03 0a 9c 00 11 04 15 58 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}