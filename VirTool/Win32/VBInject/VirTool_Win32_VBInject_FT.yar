
rule VirTool_Win32_VBInject_FT{
	meta:
		description = "VirTool:Win32/VBInject.FT,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {3b c3 db e2 7d ?? 6a 50 } //1
		$a_03_1 = {3b c3 db e2 7d ?? 6a 58 } //1
		$a_01_2 = {50 6a 01 6a ff 6a 20 ff 15 } //1
		$a_00_3 = {43 00 4e 00 54 00 42 00 52 00 41 00 00 00 } //1
		$a_00_4 = {5c 00 53 00 61 00 64 00 6f 00 6b 00 5c 00 } //1 \Sadok\
		$a_00_5 = {26 00 2f 00 26 00 25 00 26 00 28 00 3d 00 29 00 25 00 26 00 26 00 25 00 00 00 } //1
		$a_00_6 = {2e 00 45 00 58 00 45 00 00 00 } //1
		$a_00_7 = {78 00 52 00 43 00 34 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=8
 
}