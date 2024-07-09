
rule Trojan_BAT_AgentTesla_DOC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DOC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 1e 02 08 09 11 04 28 ?? ?? ?? 06 13 05 07 06 02 11 05 28 ?? ?? ?? 06 d2 9c 11 04 17 58 13 04 11 04 17 32 dd 06 17 58 0a 09 17 58 0d } //1
		$a_01_1 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_2 = {54 6f 57 69 6e 33 32 } //1 ToWin32
		$a_01_3 = {00 4c 65 76 65 6c 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}