
rule Trojan_BAT_AgentTesla_ERI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ERI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 06 09 28 90 01 03 06 26 08 07 06 09 28 90 01 03 06 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 0c 06 17 d6 0a 90 00 } //1
		$a_03_1 = {0c 07 03 17 da 93 0d 08 03 04 6f 90 01 03 0a 5d 93 13 04 09 11 04 da 90 09 0d 00 02 6f 90 01 03 0a 0b 04 6f 90 01 03 0a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}