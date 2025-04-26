
rule Ransom_Win64_Rhysida_YAA_MTB{
	meta:
		description = "Ransom:Win64/Rhysida.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {25 50 44 46 2d 31 2e 34 } //10 %PDF-1.4
		$a_01_1 = {63 79 62 65 72 73 65 63 75 72 69 74 79 20 74 65 61 6d 20 52 68 79 73 69 64 61 } //1 cybersecurity team Rhysida
		$a_01_2 = {77 69 74 68 20 79 6f 75 72 20 73 65 63 72 65 74 20 6b 65 79 } //1 with your secret key
		$a_01_3 = {72 65 67 20 61 64 64 20 22 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 41 63 74 69 76 65 44 65 73 6b 74 6f 70 22 20 2f 76 20 4e 6f 43 68 61 6e 67 69 6e 67 57 61 6c 6c 50 61 70 65 72 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 31 20 2f 66 } //1 reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" /v NoChangingWallPaper /t REG_SZ /d 1 /f
		$a_01_4 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //1 vssadmin.exe Delete Shadows /All /Quiet
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}