
rule Trojan_Win64_BroPass_C_MTB{
	meta:
		description = "Trojan:Win64/BroPass.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_01_0 = {42 72 61 76 65 53 6f 66 74 77 61 72 65 2f 42 72 61 76 65 2d 42 72 6f 77 73 65 72 2f 55 73 65 72 20 44 61 74 61 2f } //2 BraveSoftware/Brave-Browser/User Data/
		$a_01_1 = {47 6f 6f 67 6c 65 2f 43 68 72 6f 6d 65 20 42 65 74 61 2f 55 73 65 72 20 44 61 74 61 } //2 Google/Chrome Beta/User Data
		$a_01_2 = {4d 6f 7a 69 6c 6c 61 2f 46 69 72 65 66 6f 78 2f 50 72 6f 66 69 6c 65 73 } //2 Mozilla/Firefox/Profiles
		$a_01_3 = {45 78 70 6f 72 74 20 70 61 73 73 77 6f 72 64 73 2f 63 6f 6f 6b 69 65 73 2f 68 69 73 74 6f 72 79 2f 62 6f 6f 6b 6d 61 72 6b 73 20 66 72 6f 6d 20 62 72 6f 77 73 65 72 } //2 Export passwords/cookies/history/bookmarks from browser
		$a_01_4 = {68 61 63 6b 2d 62 72 6f 77 73 65 72 2d 64 61 74 61 } //3 hack-browser-data
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*3) >=11
 
}