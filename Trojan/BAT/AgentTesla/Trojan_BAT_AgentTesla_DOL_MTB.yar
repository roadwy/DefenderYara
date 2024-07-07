
rule Trojan_BAT_AgentTesla_DOL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DOL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {16 13 05 2b 24 00 02 09 11 04 11 05 28 90 01 03 06 13 06 17 13 07 08 07 02 11 06 28 90 01 03 06 d2 9c 00 11 05 17 58 13 05 11 05 17 fe 04 13 08 11 08 2d d1 07 17 58 0b 00 11 04 17 58 13 04 90 00 } //1
		$a_01_1 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_2 = {54 6f 57 69 6e 33 32 } //1 ToWin32
		$a_01_3 = {00 4c 65 76 65 6c 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}