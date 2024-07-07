
rule Trojan_BAT_AgentTesla_OR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {25 16 09 8c 90 02 04 a2 25 17 11 90 01 01 8c 90 02 04 a2 28 90 02 04 25 90 02 02 26 90 02 02 fe 90 02 05 11 90 01 01 2b 90 01 01 a5 90 02 04 13 90 01 01 11 90 01 01 28 90 00 } //1
		$a_81_1 = {54 6f 57 69 6e 33 32 } //1 ToWin32
		$a_81_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_81_3 = {67 65 74 5f 48 65 69 67 68 74 } //1 get_Height
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}