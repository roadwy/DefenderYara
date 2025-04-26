
rule Ransom_Win32_MedusaLocker_PA_MTB{
	meta:
		description = "Ransom:Win32/MedusaLocker.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 6c 6c 20 79 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 } //1 All your important files have been encrypted!
		$a_01_1 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 73 61 66 65 21 20 4f 6e 6c 79 20 6d 6f 64 69 66 69 65 64 } //1 Your files are safe! Only modified
		$a_01_2 = {44 4f 20 4e 4f 54 20 4d 4f 44 49 46 59 20 45 4e 43 52 59 50 54 45 44 20 46 49 4c 45 53 } //1 DO NOT MODIFY ENCRYPTED FILES
		$a_01_3 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //1 vssadmin.exe Delete Shadows /All /Quiet
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Ransom_Win32_MedusaLocker_PA_MTB_2{
	meta:
		description = "Ransom:Win32/MedusaLocker.PA!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 65 00 78 00 65 00 20 00 44 00 65 00 6c 00 65 00 74 00 65 00 20 00 53 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 41 00 6c 00 6c 00 20 00 2f 00 51 00 75 00 69 00 65 00 74 00 } //1 vssadmin.exe Delete Shadows /All /Quiet
		$a_01_1 = {62 00 63 00 64 00 65 00 64 00 69 00 74 00 2e 00 65 00 78 00 65 00 20 00 2f 00 73 00 65 00 74 00 20 00 7b 00 64 00 65 00 66 00 61 00 75 00 6c 00 74 00 7d 00 20 00 72 00 65 00 63 00 6f 00 76 00 65 00 72 00 79 00 65 00 6e 00 61 00 62 00 6c 00 65 00 64 00 20 00 4e 00 6f 00 } //1 bcdedit.exe /set {default} recoveryenabled No
		$a_01_2 = {77 00 62 00 61 00 64 00 6d 00 69 00 6e 00 20 00 44 00 45 00 4c 00 45 00 54 00 45 00 20 00 53 00 59 00 53 00 54 00 45 00 4d 00 53 00 54 00 41 00 54 00 45 00 42 00 41 00 43 00 4b 00 55 00 50 00 20 00 2d 00 64 00 65 00 6c 00 65 00 74 00 65 00 4f 00 6c 00 64 00 65 00 73 00 74 00 } //1 wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest
		$a_01_3 = {5b 00 4c 00 4f 00 43 00 4b 00 45 00 52 00 20 00 58 00 50 00 5d 00 20 00 4b 00 69 00 6c 00 6c 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 65 00 73 00 } //1 [LOCKER XP] Kill processes
		$a_01_4 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 2c 20 61 6e 64 20 63 75 72 72 65 6e 74 6c 79 20 75 6e 61 76 61 69 6c 61 62 6c 65 2e } //1 Your files are encrypted, and currently unavailable.
		$a_01_5 = {4d 65 64 75 73 61 4c 6f 63 6b 65 72 } //1 MedusaLocker
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}