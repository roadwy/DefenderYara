
rule Backdoor_Win32_Popwin_gen_G{
	meta:
		description = "Backdoor:Win32/Popwin.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 45 ee 49 c6 45 ef 45 c6 45 f0 2e c6 45 f1 77 c6 45 f2 6f c6 45 f3 72 c6 45 f4 6d c6 45 f5 69 c6 45 f6 65 8d 45 e8 8d 55 ee b9 09 00 00 00 } //1
		$a_03_1 = {7e 4e bb 01 00 00 00 8b 45 fc 8a 44 18 ff 24 0f 8b 55 e8 8a 54 32 ff 80 e2 0f 32 c2 88 45 f7 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 8a 54 1a ff 80 e2 f0 8a 4d f7 02 d1 88 54 18 ff } //1
		$a_00_2 = {70 6f 70 77 69 6e 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}