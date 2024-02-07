
rule PWS_Win32_OnLineGames_CPF{
	meta:
		description = "PWS:Win32/OnLineGames.CPF,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {77 69 6e 63 68 61 74 33 32 2e 64 6c 6c } //0a 00  winchat32.dll
		$a_01_1 = {00 4a 75 6d 70 4f 6e } //0a 00 
		$a_00_2 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //0a 00  OpenProcess
		$a_00_3 = {48 4d 5f 50 4f 53 54 57 4f 57 44 4c 4c } //01 00  HM_POSTWOWDLL
		$a_00_4 = {48 4d 5f 50 4f 53 54 57 49 4e 44 4f 57 44 4c 4c } //01 00  HM_POSTWINDOWDLL
		$a_00_5 = {48 4d 5f 50 4f 53 54 57 49 4e 44 4f 57 45 58 45 } //00 00  HM_POSTWINDOWEXE
	condition:
		any of ($a_*)
 
}