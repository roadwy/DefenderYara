
rule HackTool_Win32_Wincred_H{
	meta:
		description = "HackTool:Win32/Wincred.H,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 43 45 53 45 52 56 49 43 45 00 } //1
		$a_01_1 = {28 57 69 6e 64 6f 77 73 20 43 72 65 64 65 6e 74 69 61 6c 73 20 45 64 69 74 6f 72 29 } //1 (Windows Credentials Editor)
		$a_01_2 = {55 73 69 6e 67 20 57 43 45 20 57 69 6e 64 6f 77 73 20 53 65 72 76 69 63 65 2e 2e 2e } //1 Using WCE Windows Service...
		$a_01_3 = {73 6f 6d 65 74 68 69 6e 67 20 74 65 72 72 69 62 6c 65 20 68 61 70 70 65 6e 65 64 21 } //1 something terrible happened!
		$a_01_4 = {43 61 6e 6e 6f 74 20 67 65 74 20 4c 53 41 53 53 2e 45 58 45 20 50 49 44 21 } //1 Cannot get LSASS.EXE PID!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}