
rule Trojan_BAT_AgentTesla_LSC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LSC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 1f 11 06 07 08 28 90 01 03 06 13 08 11 08 28 90 01 03 0a 13 09 11 04 09 11 09 d2 9c 08 17 58 0c 08 17 fe 04 13 0a 11 0a 2d d7 90 00 } //1
		$a_01_1 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}