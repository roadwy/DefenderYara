
rule Trojan_Win64_ReverseShell_VGZ_MTB{
	meta:
		description = "Trojan:Win64/ReverseShell.VGZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2d 00 2d 00 0c 00 00 "
		
	strings :
		$a_01_0 = {33 37 2e 31 2e 32 31 32 2e 34 34 } //10 37.1.212.44
		$a_01_1 = {31 39 32 2e 31 36 38 2e 31 37 34 2e 31 34 32 } //10 192.168.174.142
		$a_01_2 = {73 76 63 5f 6c 6f 67 2e 74 78 74 } //1 svc_log.txt
		$a_01_3 = {69 6e 65 74 5f 61 64 64 72 } //10 inet_addr
		$a_01_4 = {63 6c 6f 73 65 73 6f 63 6b 65 74 } //1 closesocket
		$a_01_5 = {65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 } //1 encryptedUsername
		$a_01_6 = {65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 } //1 encryptedPassword
		$a_01_7 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 } //10 CreateProcessA
		$a_01_8 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //10 WaitForSingleObject
		$a_01_9 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //5 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_10 = {5b 46 58 20 43 6f 6f 6b 69 65 5d 20 25 73 3a 20 25 73 } //1 [FX Cookie] %s: %s
		$a_01_11 = {5b 46 58 20 42 6f 6f 6b 6d 61 72 6b 5d 20 25 73 3a 20 25 73 } //1 [FX Bookmark] %s: %s
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*10+(#a_01_8  & 1)*10+(#a_01_9  & 1)*5+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=45
 
}