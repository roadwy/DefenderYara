
rule Trojan_Win32_Fsysna_ARA_MTB{
	meta:
		description = "Trojan:Win32/Fsysna.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_80_0 = {47 6c 6f 62 61 6c 5c 33 70 63 36 52 57 4f 67 65 63 74 47 54 46 71 43 6f 77 78 6a 65 47 79 33 58 49 47 50 74 4c 77 4e 72 73 72 32 7a 44 63 74 59 44 34 68 41 55 35 70 6a 34 47 57 37 72 6d 38 67 48 72 48 79 54 42 36 } //Global\3pc6RWOgectGTFqCowxjeGy3XIGPtLwNrsr2zDctYD4hAU5pj4GW7rm8gHrHyTB6  2
		$a_80_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //Software\Microsoft\Windows\CurrentVersion\Run  2
		$a_80_2 = {6f 6e 73 61 70 61 79 2e 63 6f 6d 2f 6c 6f 61 64 65 72 } //onsapay.com/loader  2
		$a_01_3 = {5c 54 45 4d 50 5c 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 2e 65 78 65 } //2 \TEMP\AAAAAAAAAAAAAAA.exe
		$a_01_4 = {5c 54 45 4d 50 5c 73 70 6f 6f 6c 73 76 2e 65 78 65 } //2 \TEMP\spoolsv.exe
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}