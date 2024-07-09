
rule Trojan_BAT_AgentTesla_NBP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 23 11 06 07 08 28 ?? ?? ?? 06 13 07 11 07 28 ?? ?? ?? 0a 13 08 11 05 07 11 08 d2 6f ?? ?? ?? 0a 08 17 58 0c 08 17 fe 04 13 09 11 09 2d d3 } //10
		$a_03_1 = {16 13 05 2b 2c 00 09 11 04 11 05 28 ?? ?? ?? 06 13 08 11 08 28 ?? ?? ?? 0a 13 09 17 13 0a 08 11 04 11 09 d2 6f ?? ?? ?? 0a 00 00 11 05 17 58 13 05 11 05 17 fe 04 13 0b 11 0b 2d c9 07 } //10
		$a_01_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*1) >=11
 
}