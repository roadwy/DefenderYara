
rule HackTool_Win32_SysInject_A_MTB{
	meta:
		description = "HackTool:Win32/SysInject.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 00 79 00 73 00 74 00 65 00 6d 00 20 00 49 00 6e 00 6a 00 65 00 63 00 6b 00 74 00 69 00 6f 00 6e 00 33 00 32 00 20 00 2d 00 20 00 50 00 6f 00 69 00 6e 00 74 00 42 00 6c 00 61 00 6e 00 6b 00 2e 00 65 00 78 00 65 00 } //1 System Injecktion32 - PointBlank.exe
		$a_00_1 = {4b 00 75 00 74 00 65 00 6e 00 67 00 30 00 37 00 2e 00 64 00 6c 00 6c 00 } //1 Kuteng07.dll
		$a_00_2 = {72 00 69 00 6b 00 69 00 2e 00 62 00 6c 00 69 00 74 00 7a 00 } //1 riki.blitz
		$a_00_3 = {69 00 6e 00 76 00 69 00 73 00 69 00 62 00 6c 00 65 00 } //1 invisible
		$a_00_4 = {4e 6f 74 48 61 63 6b 65 72 4b 69 65 65 2e 42 6c 6f 67 73 70 6f 74 2e 43 6f 6d } //1 NotHackerKiee.Blogspot.Com
		$a_02_5 = {52 00 69 00 6b 00 69 00 42 00 4c 00 69 00 54 00 7a 00 [0-10] 2e 00 65 00 78 00 65 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_02_5  & 1)*1) >=5
 
}