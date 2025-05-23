
rule HackTool_Win32_ImpacketExec_SB{
	meta:
		description = "HackTool:Win32/ImpacketExec.SB,SIGNATURE_TYPE_CMDHSTR_EXT,1f 00 1f 00 09 00 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 51 00 20 00 2f 00 63 00 } //10 cmd.exe /Q /c
		$a_00_1 = {31 00 3e 00 20 00 5c 00 5c 00 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 5c 00 41 00 44 00 4d 00 49 00 4e 00 24 00 5c 00 5f 00 } //10 1> \\127.0.0.1\ADMIN$\_
		$a_00_2 = {32 00 3e 00 26 00 31 00 } //10 2>&1
		$a_00_3 = {3a 00 5c 00 75 00 73 00 65 00 72 00 73 00 5c 00 70 00 75 00 62 00 6c 00 69 00 63 00 5c 00 } //1 :\users\public\
		$a_00_4 = {3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 68 00 65 00 6c 00 70 00 5c 00 } //1 :\windows\help\
		$a_00_5 = {3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 76 00 73 00 73 00 5c 00 } //1 :\windows\vss\
		$a_00_6 = {3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 6c 00 6f 00 67 00 73 00 5c 00 } //1 :\windows\logs\
		$a_00_7 = {3a 00 5c 00 70 00 65 00 72 00 66 00 6c 00 6f 00 67 00 73 00 5c 00 } //1 :\perflogs\
		$a_00_8 = {3a 00 5c 00 72 00 65 00 63 00 6f 00 76 00 65 00 72 00 79 00 5c 00 } //1 :\recovery\
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=31
 
}