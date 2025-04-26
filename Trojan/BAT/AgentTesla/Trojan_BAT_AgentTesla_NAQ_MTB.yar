
rule Trojan_BAT_AgentTesla_NAQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 13 05 2b 29 00 09 11 04 11 05 28 ?? ?? ?? 06 13 08 11 08 28 ?? ?? ?? 0a 13 09 08 11 04 11 09 d2 6f ?? ?? ?? 0a 00 00 11 05 17 58 13 05 11 05 17 fe 04 13 0a 11 0a 2d cc 07 17 58 0b } //10
		$a_01_1 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_03_2 = {13 09 2b 2b 00 11 07 11 08 11 09 28 ?? ?? ?? 06 13 0b 11 0b 28 ?? ?? ?? 0a 13 0c 11 06 11 08 11 0c d2 6f ?? ?? ?? 0a 00 00 11 09 17 58 13 09 11 09 17 fe 04 13 0d 11 0d 2d ca } //10
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_03_2  & 1)*10) >=11
 
}