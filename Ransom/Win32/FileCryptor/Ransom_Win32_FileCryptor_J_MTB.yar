
rule Ransom_Win32_FileCryptor_J_MTB{
	meta:
		description = "Ransom:Win32/FileCryptor.J!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {45 6e 63 72 79 70 74 44 61 74 61 } //1 EncryptData
		$a_01_1 = {67 65 74 5f 70 61 79 6c 6f 61 64 } //1 get_payload
		$a_01_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 74 61 73 6b 6d 67 72 2e 65 78 65 } //1 taskkill /f /im taskmgr.exe
		$a_01_3 = {77 6d 69 63 20 75 73 65 72 61 63 63 6f 75 6e 74 20 77 68 65 72 65 20 6e 61 6d 65 3d 27 25 75 73 65 72 6e 61 6d 65 25 27 20 72 65 6e 61 6d 65 20 27 49 54 27 } //1 wmic useraccount where name='%username%' rename 'IT'
		$a_01_4 = {64 65 6c 20 2f 66 20 2f 73 20 2f 71 20 25 75 73 65 72 70 72 6f 66 69 6c 65 25 5c 44 65 73 6b 74 6f 70 5c } //1 del /f /s /q %userprofile%\Desktop\
		$a_01_5 = {64 65 6c 20 2f 66 20 2f 73 20 2f 71 20 22 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 57 69 6e 64 6f 77 73 41 70 70 73 } //1 del /f /s /q "C:\Program Files\WindowsApps
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}