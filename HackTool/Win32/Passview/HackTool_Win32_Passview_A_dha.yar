
rule HackTool_Win32_Passview_A_dha{
	meta:
		description = "HackTool:Win32/Passview.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 07 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 74 65 63 74 65 64 20 53 74 6f 72 61 67 65 20 50 61 73 73 56 69 65 77 } //1 Protected Storage PassView
		$a_00_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 64 6f 77 73 20 4d 65 73 73 61 67 69 6e 67 20 53 75 62 73 79 73 74 65 6d 5c 50 72 6f 66 69 6c 65 73 } //1 Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles
		$a_00_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 66 66 69 63 65 5c 4f 75 74 6c 6f 6f 6b 5c 4f 4d 49 20 41 63 63 6f 75 6e 74 20 4d 61 6e 61 67 65 72 5c 41 63 63 6f 75 6e 74 73 } //1 Software\Microsoft\Office\Outlook\OMI Account Manager\Accounts
		$a_01_3 = {6d 73 20 69 65 20 66 74 70 20 50 61 73 73 77 6f 72 64 73 } //1 ms ie ftp Passwords
		$a_01_4 = {69 6e 65 74 63 6f 6d 6d 20 73 65 72 76 65 72 20 70 61 73 73 77 6f 72 64 73 } //1 inetcomm server passwords
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 6e 74 65 6c 6c 69 46 6f 72 6d 73 5c 53 50 57 } //1 Software\Microsoft\Internet Explorer\IntelliForms\SPW
		$a_01_6 = {35 65 37 65 38 31 30 30 2d 39 31 33 38 2d 31 31 64 31 2d 39 34 35 61 2d 30 30 63 30 34 66 63 33 30 38 66 66 } //1 5e7e8100-9138-11d1-945a-00c04fc308ff
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=100
 
}