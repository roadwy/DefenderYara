
rule Trojan_BAT_AgentTesla_LRA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 23 02 11 04 06 07 28 ?? ?? ?? 06 13 05 11 05 28 ?? ?? ?? 0a 13 06 09 08 11 06 28 ?? ?? ?? 0a 9c 07 17 58 0b 07 17 fe 04 13 07 11 07 2d d3 } //1
		$a_01_1 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}