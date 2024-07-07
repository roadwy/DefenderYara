
rule VirTool_Win32_CeeInject_gen_CX{
	meta:
		description = "VirTool:Win32/CeeInject.gen!CX,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {50 51 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 6a 00 52 ff d7 8b 4c 24 90 01 01 8d 84 24 90 00 } //1
		$a_02_1 = {6a 00 52 51 8b 4c 24 90 01 01 50 51 ff 15 90 01 04 85 c0 0f 84 90 01 04 8b 44 24 90 00 } //1
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
		$a_00_3 = {41 6c 74 44 65 66 61 75 6c 74 55 73 65 72 4e 61 6d 65 } //1 AltDefaultUserName
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}