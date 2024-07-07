
rule Ransom_Win32_FileCrypter_MTB{
	meta:
		description = "Ransom:Win32/FileCrypter!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0d 00 00 "
		
	strings :
		$a_81_0 = {74 78 74 7c 76 62 73 7c 6a 73 70 7c 70 68 70 7c 77 61 76 7c 73 77 66 7c 77 6d 76 7c 6d 70 67 7c 6d 70 65 67 7c 61 76 69 7c 6d 6f 76 7c 6d 6b 76 7c 66 6c 76 7c 73 76 67 7c 70 73 64 7c 67 69 66 7c 62 6d 70 7c 69 73 6f 7c 62 63 6b } //1 txt|vbs|jsp|php|wav|swf|wmv|mpg|mpeg|avi|mov|mkv|flv|svg|psd|gif|bmp|iso|bck
		$a_81_1 = {64 6f 77 6e 6c 6f 61 64 2f 44 65 63 72 79 70 74 6f 72 2e 65 78 65 } //1 download/Decryptor.exe
		$a_81_2 = {64 6f 77 6e 6c 6f 61 64 2f 42 61 63 6b 64 6f 6f 72 2e 65 78 65 } //1 download/Backdoor.exe
		$a_81_3 = {52 41 4e 53 4f 4d 57 41 52 45 5f 53 45 43 } //1 RANSOMWARE_SEC
		$a_81_4 = {50 53 4e 53 4f 4d 57 41 52 45 20 2d 20 41 20 50 53 4e 20 52 41 4e 53 4f 4d 57 41 52 45 20 2d 20 43 61 6e 27 74 20 65 78 65 63 75 74 65 20 21 } //1 PSNSOMWARE - A PSN RANSOMWARE - Can't execute !
		$a_81_5 = {22 64 65 63 72 79 70 74 69 6f 6e 2d 6b 65 79 22 3a } //1 "decryption-key":
		$a_81_6 = {5c 41 70 70 44 61 74 61 5c 70 73 6e 6f 6d 77 61 72 65 } //1 \AppData\psnomware
		$a_81_7 = {2e 70 73 6e 6f 6d 77 61 72 65 } //1 .psnomware
		$a_81_8 = {5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 62 61 63 6b 64 6f 6f 72 2e 65 78 65 } //1 \AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\backdoor.exe
		$a_81_9 = {5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 72 65 61 64 6d 65 2e 68 74 6d 6c } //1 \AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\readme.html
		$a_81_10 = {3c 74 69 74 6c 65 3e 50 53 4e 4f 4d 57 41 52 45 20 72 61 6e 73 6f 6d 77 61 72 65 3c 2f 74 69 74 6c 65 3e } //1 <title>PSNOMWARE ransomware</title>
		$a_81_11 = {5c 44 65 73 6b 74 6f 70 5c 44 65 63 72 79 70 74 6f 72 2e 65 78 65 } //1 \Desktop\Decryptor.exe
		$a_81_12 = {5c 44 65 73 6b 74 6f 70 5c 52 45 41 44 4d 45 2e 48 54 4d 4c } //1 \Desktop\README.HTML
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1) >=10
 
}