
rule Ransom_Win32_Filecoder_MB_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_01_0 = {6f 00 77 00 6c 00 73 00 75 00 70 00 70 00 6f 00 72 00 74 00 40 00 64 00 65 00 63 00 6f 00 79 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //5 owlsupport@decoymail.com
		$a_01_1 = {6f 00 77 00 6c 00 61 00 64 00 6d 00 69 00 6e 00 40 00 6f 00 6e 00 69 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 6f 00 72 00 67 00 } //5 owladmin@onionmail.org
		$a_01_2 = {5f 6c 6f 63 6b 5f 66 69 6c 65 } //1 _lock_file
		$a_01_3 = {5f 4c 6f 63 6b 69 74 } //1 _Lockit
		$a_01_4 = {73 74 61 72 74 20 69 6e 66 6f 2e 74 78 74 } //1 start info.txt
		$a_01_5 = {69 00 6e 00 66 00 6f 00 2e 00 74 00 78 00 74 00 } //1 info.txt
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=14
 
}
rule Ransom_Win32_Filecoder_MB_MTB_2{
	meta:
		description = "Ransom:Win32/Filecoder.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 07 00 00 "
		
	strings :
		$a_01_0 = {72 61 6e 73 6f 6d 77 61 72 65 30 30 31 2e 70 64 62 } //5 ransomware001.pdb
		$a_01_1 = {3c 74 61 72 67 65 74 20 64 69 72 65 63 74 6f 72 79 3e 20 5b 2f 76 5d 20 5b 2f 73 5d 20 5b 2f 6f 5d 20 5b 2f 61 5d 20 5b 2f 72 5d 20 5b 2d 63 20 3c 6e 75 6d 62 65 72 3e 5d 20 5b 2d 64 20 3c 73 65 63 6f 6e 64 3e 5d } //1 <target directory> [/v] [/s] [/o] [/a] [/r] [-c <number>] [-d <second>]
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {72 61 6e 73 6f 6d 77 61 72 65 } //1 ransomware
		$a_01_4 = {76 20 3d 20 76 65 72 62 6f 73 65 2c 20 70 72 69 6e 74 20 61 6c 6c 20 6c 6f 67 73 20 66 6f 72 20 64 65 62 75 67 67 69 6e 67 } //1 v = verbose, print all logs for debugging
		$a_01_5 = {72 20 3d 20 72 65 67 69 73 74 72 79 2c 20 61 64 64 20 74 68 65 20 70 72 6f 67 72 61 6d 20 74 6f 20 74 68 65 20 57 69 6e 64 6f 77 73 20 73 74 61 72 74 2d 75 70 } //1 r = registry, add the program to the Windows start-up
		$a_01_6 = {63 6f 6e 74 69 6e 75 6f 75 73 20 6e 75 6d 62 65 72 20 6f 66 20 66 69 6c 65 73 20 74 6f 20 62 65 20 65 6e 63 72 79 70 74 65 64 } //1 continuous number of files to be encrypted
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=11
 
}