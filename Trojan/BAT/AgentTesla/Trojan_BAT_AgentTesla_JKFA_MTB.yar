
rule Trojan_BAT_AgentTesla_JKFA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JKFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 16 68 00 00 0b 2b 1d 00 06 07 23 33 33 33 33 33 e3 6f 40 28 90 01 03 0a 69 28 90 01 03 06 0a 00 07 15 58 0b 07 16 fe 04 16 fe 01 0c 08 2d d8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}