
rule PWS_Win32_OnLineGames_CPL_dr{
	meta:
		description = "PWS:Win32/OnLineGames.CPL!dr,SIGNATURE_TYPE_PEHSTR_EXT,6c 00 6c 00 0b 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {4a 75 6d 70 4f 6e } //1 JumpOn
		$a_01_2 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_00_3 = {57 72 69 74 65 46 69 6c 65 } //1 WriteFile
		$a_00_4 = {46 69 6e 64 57 69 6e 64 6f 77 } //1 FindWindow
		$a_00_5 = {47 65 74 4b 65 79 62 6f 61 72 64 54 79 70 65 } //1 GetKeyboardType
		$a_00_6 = {48 4d 58 49 45 42 4a 43 } //1 HMXIEBJC
		$a_00_7 = {48 4d 5f 54 43 4c 57 4f 57 53 4a 5f 49 4e 46 4f } //1 HM_TCLWOWSJ_INFO
		$a_00_8 = {0b 00 00 00 77 73 6d 73 63 7a 78 2e 64 6c 6c 00 48 4d 5f 4d 45 53 53 57 4f 57 41 47 45 57 5a 48 55 5a 48 55 57 44 4c 4c 00 00 00 00 48 4d 5f 4d 45 53 53 57 4f 57 5a 48 55 5a 48 55 44 4c 4c 00 ff ff ff ff 32 00 00 00 } //100
		$a_00_9 = {48 4d 5f 54 43 4c 44 41 4f 4a 49 41 4e 53 4a 5f 49 4e 46 4f } //1 HM_TCLDAOJIANSJ_INFO
		$a_00_10 = {0b 00 00 00 67 64 64 6a 69 33 32 2e 64 6c 6c 00 48 4d 5f 4d 45 53 53 44 41 4f 4a 41 47 45 57 4c 49 55 4c 49 55 57 44 4c 4c 00 00 00 48 4d 5f 4d 45 53 53 44 41 4f 4a 4c 49 55 4c 49 55 44 4c 4c 00 00 00 00 ff ff ff ff 32 00 00 00 } //100
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*100+(#a_00_9  & 1)*1+(#a_00_10  & 1)*100) >=108
 
}