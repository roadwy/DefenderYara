
rule Ransom_Win32_Seven_MAK_MTB{
	meta:
		description = "Ransom:Win32/Seven.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_81_0 = {52 45 47 20 41 44 44 20 22 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 22 20 2f 76 20 22 61 6c 6c 6b 65 65 70 65 72 22 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 } //1 REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "allkeeper" /t REG_SZ /d
		$a_81_1 = {52 45 47 20 41 44 44 20 22 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 4f 46 54 57 41 52 45 22 20 2f 76 20 22 74 65 73 74 64 65 63 72 79 70 74 22 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 } //1 REG ADD "HKEY_CURRENT_USER\SOFTWARE" /v "testdecrypt" /t REG_SZ /d
		$a_81_2 = {5c 64 65 6c 2e 62 61 74 } //1 \del.bat
		$a_81_3 = {52 45 47 20 41 44 44 20 22 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 4f 46 54 57 41 52 45 22 20 2f 76 20 22 44 65 63 72 79 70 74 35 30 22 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 } //1 REG ADD "HKEY_CURRENT_USER\SOFTWARE" /v "Decrypt50" /t REG_SZ /d
		$a_81_4 = {59 6f 75 20 68 61 76 65 20 74 6f 20 70 61 79 20 77 69 74 68 69 6e 20 37 32 20 68 6f 75 72 73 } //1 You have to pay within 72 hours
		$a_81_5 = {69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 73 74 72 6f 6e 67 20 61 6c 67 6f 72 69 74 68 6d } //1 important files were encrypted with strong algorithm
		$a_81_6 = {59 4f 55 52 20 50 45 52 53 4f 4e 41 4c 20 46 49 4c 45 53 20 57 45 52 45 20 45 4e 43 52 59 50 54 45 44 20 42 59 20 37 65 76 33 6e 2d 48 4f 4e 45 24 54 } //1 YOUR PERSONAL FILES WERE ENCRYPTED BY 7ev3n-HONE$T
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=6
 
}