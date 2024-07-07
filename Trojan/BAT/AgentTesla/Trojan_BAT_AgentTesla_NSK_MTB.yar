
rule Trojan_BAT_AgentTesla_NSK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {11 03 11 06 02 11 06 91 11 02 18 d6 18 da 61 11 01 11 07 19 d6 19 da 91 61 b4 9c 20 } //1
		$a_01_1 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_3 = {54 6f 41 72 67 62 } //1 ToArgb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}