
rule Trojan_BAT_AgentTesla_NBC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 27 00 08 09 11 04 28 90 01 03 06 13 06 11 06 28 90 01 03 0a 13 07 07 09 11 07 d2 6f 90 01 03 0a 00 00 11 04 17 58 13 04 11 04 17 fe 04 13 08 11 08 2d ce 90 00 } //1
		$a_01_1 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}