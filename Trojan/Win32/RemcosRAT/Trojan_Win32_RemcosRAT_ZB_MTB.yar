
rule Trojan_Win32_RemcosRAT_ZB_MTB{
	meta:
		description = "Trojan:Win32/RemcosRAT.ZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //1 \AppData\Local\Google\Chrome\User Data\Default\Login Data
		$a_01_1 = {5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 43 6f 6f 6b 69 65 73 } //1 \AppData\Local\Google\Chrome\User Data\Default\Cookies
		$a_01_2 = {41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 50 72 6f 66 69 6c 65 73 5c } //1 AppData\Roaming\Mozilla\Firefox\Profiles\
		$a_01_3 = {5c 6c 6f 67 69 6e 73 2e 6a 73 6f 6e } //1 \logins.json
		$a_01_4 = {5c 6b 65 79 33 2e 64 62 } //1 \key3.db
		$a_01_5 = {41 67 65 6e 74 20 69 6e 69 74 69 61 6c 69 7a 65 64 } //1 Agent initialized
		$a_01_6 = {41 63 63 65 73 73 20 4c 65 76 65 6c 3a } //1 Access Level:
		$a_01_7 = {41 64 6d 69 6e 69 73 74 72 61 74 6f 72 } //1 Administrator
		$a_01_8 = {53 74 61 72 74 46 6f 72 77 61 72 64 } //1 StartForward
		$a_01_9 = {53 74 61 72 74 52 65 76 65 72 73 65 } //1 StartReverse
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}