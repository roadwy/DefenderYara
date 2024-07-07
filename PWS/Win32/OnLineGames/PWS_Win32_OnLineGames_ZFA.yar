
rule PWS_Win32_OnLineGames_ZFA{
	meta:
		description = "PWS:Win32/OnLineGames.ZFA,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {61 63 63 6f 75 6e 74 6e 61 6d 65 } //1 accountname
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {77 6f 77 2e 65 78 65 } //1 wow.exe
		$a_01_3 = {25 73 5c 65 25 64 55 50 2e 65 78 65 } //1 %s\e%dUP.exe
		$a_01_4 = {73 65 63 72 65 74 51 75 65 73 74 69 6f 6e 41 6e 73 77 65 72 } //1 secretQuestionAnswer
		$a_01_5 = {73 77 6f 77 2e 61 73 70 } //1 swow.asp
		$a_01_6 = {72 65 61 6c 6d 6c 69 73 74 2e 77 74 66 } //1 realmlist.wtf
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}