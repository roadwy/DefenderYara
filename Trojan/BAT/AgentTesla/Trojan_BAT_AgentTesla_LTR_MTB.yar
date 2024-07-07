
rule Trojan_BAT_AgentTesla_LTR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LTR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 27 00 08 09 11 04 28 90 01 03 06 13 08 11 08 28 90 01 03 0a 13 09 07 09 11 09 d2 6f 90 01 03 0a 00 00 11 04 17 58 13 04 11 04 17 fe 04 13 0a 11 0a 2d ce 90 00 } //5
		$a_01_1 = {47 00 65 00 74 00 50 00 69 00 78 00 65 00 6c } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}