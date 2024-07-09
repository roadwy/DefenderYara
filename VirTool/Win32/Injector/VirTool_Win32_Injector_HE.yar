
rule VirTool_Win32_Injector_HE{
	meta:
		description = "VirTool:Win32/Injector.HE,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {db 45 dc dc 1d ?? ?? ?? ?? df e0 f6 c4 41 75 ?? 68 ?? ?? ?? ?? 6a 00 8d 95 ?? ?? ?? ?? ff d2 } //1
		$a_03_1 = {32 d8 88 9c 3d [0-22] f7 6d d8 c1 fa 08 8b c2 c1 e8 1f 03 d0 02 84 15 ?? ?? ?? ?? 3c 05 8d 8c 15 ?? ?? ?? ?? 77 [0-18] f7 6d e0 c1 fa 03 8b c2 c1 e8 1f 03 d0 8a 94 15 ?? ?? ?? ?? fe ca 88 11 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}