
rule Ransom_Win64_LockFile_NVA_MTB{
	meta:
		description = "Ransom:Win64/LockFile.NVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 07 00 00 "
		
	strings :
		$a_81_0 = {59 4f 55 52 5f 46 49 4c 45 53 5f 45 4e 43 52 59 50 54 45 44 2e 74 78 74 } //2 YOUR_FILES_ENCRYPTED.txt
		$a_81_1 = {52 45 41 44 4d 45 5f 42 59 5f 44 57 45 59 2e 74 78 74 } //1 README_BY_DWEY.txt
		$a_81_2 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 68 61 73 20 62 65 65 6e 20 61 74 74 61 63 6b 65 64 20 62 79 20 43 61 62 62 69 74 20 4c 6f 63 6b } //1 Your computer has been attacked by Cabbit Lock
		$a_81_3 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 43 6f 6d 6d 61 6e 64 20 22 47 65 74 2d 50 6e 70 44 65 76 69 63 65 20 7c 20 57 68 65 72 65 2d 4f 62 6a 65 63 74 } //1 powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command "Get-PnpDevice | Where-Object
		$a_81_4 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //2 vssadmin.exe delete shadows /all /quiet
		$a_81_5 = {64 69 73 6b 70 61 72 74 20 2f 73 20 6d 6f 75 6e 74 2e 74 78 74 20 3e 6e 75 6c 20 32 3e 26 31 } //1 diskpart /s mount.txt >nul 2>&1
		$a_81_6 = {62 63 64 65 64 69 74 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 6e 6f } //1 bcdedit /set {default} recoveryenabled no
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*2+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=9
 
}