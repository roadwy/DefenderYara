
rule Ransom_Win32_GandCrab_A_MSR{
	meta:
		description = "Ransom:Win32/GandCrab.A!MSR,SIGNATURE_TYPE_PEHSTR,03 00 03 00 07 00 00 "
		
	strings :
		$a_01_0 = {2f 46 20 2f 43 72 65 61 74 65 20 2f 54 4e 20 54 65 6e 63 65 6e 74 69 64 20 2f 73 63 20 6d 69 6e 75 74 65 20 2f 4d 4f 20 31 20 2f 54 52 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 4d 75 73 69 63 5c 74 65 6e 63 65 6e 74 73 6f 73 6f 2e 65 78 65 } //1 /F /Create /TN Tencentid /sc minute /MO 1 /TR C:\Users\Public\Music\tencentsoso.exe
		$a_01_1 = {43 00 49 00 41 00 50 00 4c 00 41 00 4e 00 } //1 CIAPLAN
		$a_01_2 = {4d 75 73 69 63 5c 63 69 61 2e 70 6c 61 6e } //1 Music\cia.plan
		$a_01_3 = {2f 43 20 72 65 67 20 61 64 64 20 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 76 20 74 65 6e 63 65 6e 74 69 64 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 22 52 75 6e 64 6c 6c 33 32 2e 65 78 65 } //1 /C reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v tencentid /t REG_SZ /d "Rundll32.exe
		$a_01_4 = {5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 4d 75 73 69 63 5c 53 69 64 65 42 61 72 2e 64 6c 6c } //1 \Users\Public\Music\SideBar.dll
		$a_01_5 = {43 49 41 2d 44 6f 6e 27 74 20 61 6e 61 6c 79 7a 65 } //1 CIA-Don't analyze
		$a_01_6 = {43 49 41 2d 41 73 69 61 50 61 63 69 66 69 63 53 74 72 61 74 65 67 79 } //1 CIA-AsiaPacificStrategy
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=3
 
}