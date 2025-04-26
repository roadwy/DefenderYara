
rule PWS_Win32_Delf_ALD{
	meta:
		description = "PWS:Win32/Delf.ALD,SIGNATURE_TYPE_PEHSTR_EXT,24 00 24 00 09 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //5 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 41 63 63 6f 75 6e 74 20 4d 61 6e 61 67 65 72 5c 41 63 63 6f 75 6e 74 73 } //5 Software\Microsoft\Internet Account Manager\Accounts
		$a_01_2 = {50 4f 50 33 20 50 61 73 73 77 6f 72 64 32 } //5 POP3 Password2
		$a_01_3 = {50 4f 50 33 20 55 73 65 72 20 4e 61 6d 65 3a 20 } //5 POP3 User Name: 
		$a_01_4 = {53 68 65 6c 6c 53 65 72 76 69 63 65 4f 62 6a 65 63 74 44 65 6c 61 79 4c 6f 61 64 } //5 ShellServiceObjectDelayLoad
		$a_01_5 = {7b 43 31 34 35 43 46 31 31 2d 31 32 34 46 2d 33 35 36 32 2d 34 34 41 43 2d 45 36 38 35 44 39 36 32 43 36 33 43 7d } //5 {C145CF11-124F-3562-44AC-E685D962C63C}
		$a_01_6 = {43 6f 6d 70 75 74 65 72 20 49 6e 66 6f 72 6d 61 74 69 6f 6e 3a } //5 Computer Information:
		$a_01_7 = {49 20 61 6d 20 49 6e 73 74 61 6c 6c 65 64 } //5 I am Installed
		$a_03_8 = {73 68 65 6c 6c 33 32 2e 64 6c 6c 2c 31 90 0f 03 00 00 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5+(#a_01_7  & 1)*5+(#a_03_8  & 1)*1) >=36
 
}