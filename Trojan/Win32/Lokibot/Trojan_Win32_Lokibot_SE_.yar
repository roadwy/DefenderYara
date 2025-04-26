
rule Trojan_Win32_Lokibot_SE_{
	meta:
		description = "Trojan:Win32/Lokibot.SE!!Lokibot.gen!SD,SIGNATURE_TYPE_ARHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_81_0 = {53 6f 66 74 77 61 72 65 5c 44 6f 77 6e 6c 6f 61 64 4d 61 6e 61 67 65 72 5c 50 61 73 73 77 6f 72 64 73 } //1 Software\DownloadManager\Passwords
		$a_81_1 = {67 65 74 5f 50 61 73 73 77 6f 72 64 } //1 get_Password
		$a_81_2 = {57 69 6e 64 6f 77 73 20 44 6f 6d 61 69 6e 20 50 61 73 73 77 6f 72 64 20 43 72 65 64 65 6e 74 69 61 6c } //1 Windows Domain Password Credential
		$a_81_3 = {44 65 63 72 79 70 74 49 65 50 61 73 73 77 6f 72 64 } //1 DecryptIePassword
		$a_81_4 = {65 6e 61 62 6c 65 50 61 73 73 77 6f 72 64 52 65 74 72 69 65 76 61 6c } //1 enablePasswordRetrieval
		$a_81_5 = {5c 46 74 70 6c 69 73 74 2e 74 78 74 } //1 \Ftplist.txt
		$a_81_6 = {5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 54 68 65 20 42 61 74 21 } //1 \AppData\Roaming\The Bat!
		$a_81_7 = {63 68 65 63 6b 69 70 2e 61 6d 61 7a 6f 6e 61 77 73 2e 63 6f 6d } //1 checkip.amazonaws.com
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=7
 
}