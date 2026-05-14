
rule Trojan_Win32_ShellLoader_KBX_MTB{
	meta:
		description = "Trojan:Win32/ShellLoader.KBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 89 c6 b8 ?? ?? ?? ?? 89 d7 f7 e9 c1 fa 04 89 c8 c1 f9 1f 29 ca 6b d2 35 89 c1 29 d0 29 c5 89 da c1 e3 04 01 d3 } //5
		$a_03_1 = {03 89 c6 b8 ?? ?? ?? ?? 89 d7 f7 e9 c1 fa 05 89 c8 c1 f9 1f 29 ca 6b d2 61 89 c1 29 d0 31 e8 89 da c1 e3 05 29 d3 31 c3 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}