
rule Ransom_Win32_FileCryptor_MAK_MTB{
	meta:
		description = "Ransom:Win32/FileCryptor.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {64 6f 63 75 6d 65 6e 74 73 20 6f 6e 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 documents on your computer are encrypted
		$a_81_1 = {48 4f 57 5f 46 49 58 5f 46 49 4c 45 53 2e 68 74 6d } //1 HOW_FIX_FILES.htm
		$a_81_2 = {72 61 6e 73 6f 6d 77 61 72 65 } //1 ransomware
		$a_81_3 = {59 6f 75 72 20 50 65 72 73 6f 6e 61 6c 20 43 4f 44 45 3a } //1 Your Personal CODE:
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Ransom_Win32_FileCryptor_MAK_MTB_2{
	meta:
		description = "Ransom:Win32/FileCryptor.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_81_0 = {2e 6f 6e 69 6f 6e 2f 67 61 74 65 2e 70 68 70 } //1 .onion/gate.php
		$a_81_1 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 2c 20 61 6e 64 20 63 75 72 72 65 6e 74 6c 79 20 75 6e 61 76 61 69 6c 61 62 6c 65 } //1 Your files are encrypted, and currently unavailable
		$a_81_2 = {79 6f 75 20 77 69 6c 6c 20 6c 6f 73 65 20 79 6f 75 72 20 74 69 6d 65 20 61 6e 64 20 64 61 74 61 } //1 you will lose your time and data
		$a_81_3 = {21 21 21 20 44 41 4e 47 45 52 20 21 21 21 } //1 !!! DANGER !!!
		$a_81_4 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //1 \\.\PhysicalDrive0
		$a_81_5 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b } //1 expand 32-byte k
		$a_81_6 = {65 6e 63 72 79 70 74 48 44 44 } //1 encryptHDD
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=6
 
}