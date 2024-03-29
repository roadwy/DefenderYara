
rule HackTool_Win32_SystemSchtaskFromPublicUser_A{
	meta:
		description = "HackTool:Win32/SystemSchtaskFromPublicUser.A,SIGNATURE_TYPE_CMDHSTR_EXT,63 00 0e 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 } //01 00  schtasks.exe
		$a_00_1 = {2f 00 43 00 72 00 65 00 61 00 74 00 65 00 } //01 00  /Create
		$a_00_2 = {2f 00 53 00 43 00 20 00 4f 00 4e 00 4c 00 4f 00 47 00 4f 00 4e 00 } //01 00  /SC ONLOGON
		$a_00_3 = {2f 00 52 00 55 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 } //01 00  /RU system
		$a_00_4 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 50 00 75 00 62 00 6c 00 69 00 63 00 5c 00 } //f6 ff  C:\Users\Public\
		$a_00_5 = {61 00 75 00 74 00 6f 00 6d 00 61 00 74 00 65 00 } //00 00  automate
	condition:
		any of ($a_*)
 
}