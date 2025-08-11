
rule Trojan_Win32_Vidar_EAAQ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.EAAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {6b 14 24 0c 01 d1 89 41 08 8b 04 24 83 c0 01 89 04 24 } //2
		$a_02_1 = {83 c4 0c 01 ef 89 bc 9e 44 1e 00 00 0f b6 0c 9d ?? ?? ?? ?? bd 01 00 00 00 d3 e5 8b 04 24 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_02_1  & 1)*2) >=4
 
}