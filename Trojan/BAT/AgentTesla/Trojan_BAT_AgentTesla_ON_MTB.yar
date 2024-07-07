
rule Trojan_BAT_AgentTesla_ON_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ON!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {25 16 09 8c 90 02 04 a2 25 17 11 90 01 01 8c 90 02 04 a2 14 14 28 90 02 04 25 2d 90 01 01 26 12 90 01 01 fe 90 02 05 11 90 01 01 2b 90 01 01 a5 90 02 04 13 90 01 01 11 90 01 01 28 90 02 04 13 90 01 01 08 06 11 90 01 01 b4 9c 11 90 01 01 17 d6 13 90 01 01 11 90 01 01 16 31 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}