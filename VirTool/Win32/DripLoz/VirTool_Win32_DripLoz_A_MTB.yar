
rule VirTool_Win32_DripLoz_A_MTB{
	meta:
		description = "VirTool:Win32/DripLoz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {05 c1 00 00 00 0f 05 48 83 f8 00 ?? ?? 49 8b cc 49 8b d5 4d 8b c6 4d 8b cf 4c 8b d1 48 33 c0 05 bd 00 00 00 0f 05 48 83 f8 00 ?? ?? ?? ?? ?? ?? 49 8b cc 49 8b d5 4d 8b c6 4d 8b cf 4c 8b d1 48 33 c0 05 bc 00 00 00 0f 05 48 83 f8 00 } //1
		$a_01_1 = {4d 8b c2 49 c7 c2 01 00 00 00 4d 33 d2 49 c7 c2 0a 00 00 00 4c 8b d1 33 c0 4d 2b c2 83 c0 18 4d 33 c0 0f 05 c3 48 83 c1 0a 33 c0 4c 8b d1 83 c0 3a 49 83 ea 0a 48 83 e9 0a 0f 05 c3 49 83 c2 1c 33 c0 4c 8b d1 49 83 ea 01 83 c0 50 49 83 c2 01 0f 05 c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}