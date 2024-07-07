
rule Trojan_BAT_AgentTesla_NZN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NZN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 06 11 08 9a 1f 10 28 90 01 01 00 00 0a 8c 90 01 01 00 00 01 6f 90 01 01 00 00 0a 26 11 08 17 58 13 08 11 08 06 8e 69 fe 04 13 09 11 09 2d d6 90 00 } //1
		$a_03_1 = {01 25 16 1f 25 9d 6f 90 01 01 00 00 0a 13 05 19 8d 90 01 01 00 00 01 25 16 11 05 16 9a a2 25 17 11 05 17 9a a2 25 18 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}