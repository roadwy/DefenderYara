
rule Trojan_BAT_AgentTesla_LTM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 28 11 04 06 07 6f 90 01 03 0a 26 11 04 06 07 6f 90 01 03 0a 13 05 11 05 28 90 01 03 0a 13 06 09 08 11 06 d2 9c 07 17 58 0b 07 17 fe 04 13 07 11 07 2d ce 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}