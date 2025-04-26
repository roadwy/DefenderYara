
rule Ransom_MSIL_CipherLocker_BSA_MTB{
	meta:
		description = "Ransom:MSIL/CipherLocker.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,52 00 52 00 0b 00 00 "
		
	strings :
		$a_81_0 = {43 69 70 68 65 72 4c 6f 63 6b 65 72 2e 65 78 65 } //50 CipherLocker.exe
		$a_81_1 = {43 69 70 68 65 72 4c 6f 63 6b 65 72 3a 20 45 6e 63 72 79 70 74 69 } //6 CipherLocker: Encrypti
		$a_81_2 = {6f 6e 20 63 6f 6d 70 6c 65 74 65 64 20 6f 6e } //4 on completed on
		$a_81_3 = {41 74 74 65 6d 70 74 69 6e 67 20 74 6f 20 65 6e 63 72 79 70 74 3a } //2 Attempting to encrypt:
		$a_81_4 = {2e 63 6c 6f 63 6b 65 72 } //2 .clocker
		$a_81_5 = {44 69 73 61 62 6c 65 64 20 53 79 73 74 65 6d 20 52 65 73 74 6f 72 65 20 50 6f 69 6e 74 73 } //2 Disabled System Restore Points
		$a_81_6 = {53 79 73 74 65 6d 20 52 65 73 74 6f 72 65 20 64 69 73 61 62 6c 65 64 } //2 System Restore disabled
		$a_81_7 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 } //2 vssadmin delete shadows
		$a_81_8 = {59 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 43 69 70 68 65 72 4c 6f 63 6b 65 72 2e } //10 Your personal files have been encrypted by CipherLocker.
		$a_81_9 = {43 69 70 68 65 72 4c 6f 63 6b 65 72 2e 52 61 6e 73 6f 6d 77 61 72 65 2b 3c 50 72 6f 63 65 73 73 46 69 6c 65 73 41 73 79 6e 63 3e } //15 CipherLocker.Ransomware+<ProcessFilesAsync>
		$a_81_10 = {43 69 70 68 65 72 4c 6f 63 6b 65 72 2e 54 65 6c 65 67 72 61 6d 4e 6f 74 69 66 69 65 72 } //15 CipherLocker.TelegramNotifier
	condition:
		((#a_81_0  & 1)*50+(#a_81_1  & 1)*6+(#a_81_2  & 1)*4+(#a_81_3  & 1)*2+(#a_81_4  & 1)*2+(#a_81_5  & 1)*2+(#a_81_6  & 1)*2+(#a_81_7  & 1)*2+(#a_81_8  & 1)*10+(#a_81_9  & 1)*15+(#a_81_10  & 1)*15) >=82
 
}