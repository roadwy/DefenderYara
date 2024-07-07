
rule VirTool_Win32_CeeInject_GP{
	meta:
		description = "VirTool:Win32/CeeInject.GP,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 8a 03 8b 95 d4 b1 ff ff 8d 14 92 0f af d6 2b c2 88 85 da b1 ff ff 90 13 8a 85 da b1 ff ff 88 03 43 4f 75 90 00 } //1
		$a_01_1 = {0f 31 89 c2 0f 31 29 d0 77 fa 64 8b 1d 30 00 00 00 8b 5b 0c 8b 5b 0c 8b 1b 8b 1b 8b 5b 18 89 5d fc 33 c0 89 c3 c6 45 a9 47 c6 45 aa 50 c6 45 ab 41 8b 45 fc 89 85 c4 fd ff ff 8b 75 fc } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}