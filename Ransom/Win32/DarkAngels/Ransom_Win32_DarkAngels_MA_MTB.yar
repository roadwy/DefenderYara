
rule Ransom_Win32_DarkAngels_MA_MTB{
	meta:
		description = "Ransom:Win32/DarkAngels.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 0a 00 00 "
		
	strings :
		$a_00_0 = {44 20 41 20 52 20 4b } //3 D A R K
		$a_00_1 = {41 20 4e 20 47 20 45 20 4c 20 53 } //3 A N G E L S
		$a_01_2 = {79 6f 75 72 20 6e 65 74 77 6f 72 6b 20 69 6e 66 72 61 73 74 72 75 63 74 75 72 65 20 68 61 73 20 62 65 65 6e 20 63 6f 6d 70 72 6f 6d 69 73 65 64 } //3 your network infrastructure has been compromised
		$a_01_3 = {62 61 63 6b 75 70 20 44 6f 6e 27 74 20 72 65 6e 61 6d 65 20 63 72 79 70 74 65 64 20 66 69 6c 65 73 20 61 6e 64 20 63 72 65 61 74 65 20 6e 6f 74 65 } //3 backup Don't rename crypted files and create note
		$a_01_4 = {61 6e 64 20 77 65 20 77 69 6c 6c 20 73 68 61 72 65 20 61 6c 6c 20 74 68 65 20 6c 65 61 6b 65 64 20 64 61 74 61 20 66 6f 72 20 66 72 65 65 } //3 and we will share all the leaked data for free
		$a_01_5 = {44 65 63 72 79 70 74 69 6f 6e 20 6b 65 79 20 77 69 6c 6c 20 62 65 20 64 65 6c 65 74 65 64 20 70 65 72 6d 61 6e 65 6e 74 6c 79 20 61 6e 64 20 72 65 63 6f 76 65 72 79 20 77 69 6c 6c 20 62 65 20 69 6d 70 6f 73 73 69 62 6c 65 } //3 Decryption key will be deleted permanently and recovery will be impossible
		$a_01_6 = {48 00 6f 00 77 00 20 00 54 00 6f 00 20 00 52 00 65 00 73 00 74 00 6f 00 72 00 65 00 20 00 59 00 6f 00 75 00 72 00 20 00 46 00 69 00 6c 00 65 00 73 00 2e 00 74 00 78 00 74 00 } //1 How To Restore Your Files.txt
		$a_01_7 = {52 00 4f 00 4f 00 54 00 5c 00 63 00 69 00 6d 00 76 00 32 00 } //1 ROOT\cimv2
		$a_01_8 = {73 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 53 00 68 00 61 00 64 00 6f 00 77 00 43 00 6f 00 70 00 79 00 } //1 select * from Win32_ShadowCopy
		$a_01_9 = {66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 files are encrypted
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=16
 
}