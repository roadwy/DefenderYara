
rule PWS_Win32_OnLineGames_CPF{
	meta:
		description = "PWS:Win32/OnLineGames.CPF,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 06 00 00 "
		
	strings :
		$a_00_0 = {77 69 6e 63 68 61 74 33 32 2e 64 6c 6c } //10 winchat32.dll
		$a_01_1 = {00 4a 75 6d 70 4f 6e } //10
		$a_00_2 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //10 OpenProcess
		$a_00_3 = {48 4d 5f 50 4f 53 54 57 4f 57 44 4c 4c } //10 HM_POSTWOWDLL
		$a_00_4 = {48 4d 5f 50 4f 53 54 57 49 4e 44 4f 57 44 4c 4c } //1 HM_POSTWINDOWDLL
		$a_00_5 = {48 4d 5f 50 4f 53 54 57 49 4e 44 4f 57 45 58 45 } //1 HM_POSTWINDOWEXE
	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=41
 
}