
rule Trojan_BAT_AgentTesla_LSN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LSN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 1f 11 05 07 08 28 90 01 03 06 13 06 11 06 28 90 01 03 0a 13 07 11 04 09 11 07 d2 9c 08 17 58 0c 08 17 fe 04 13 08 11 08 2d d7 90 00 } //1
		$a_01_1 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}