
rule Trojan_Win32_CryptBot_DB_MTB{
	meta:
		description = "Trojan:Win32/CryptBot.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffff93 01 ffffff93 01 10 00 00 "
		
	strings :
		$a_81_0 = {77 61 6c 6c 65 74 2e 64 61 74 } //100 wallet.dat
		$a_81_1 = {6c 6f 67 69 6e 73 2e 6a 73 6f 6e } //100 logins.json
		$a_81_2 = {63 6f 6f 6b 69 65 73 2e 73 71 6c 69 74 65 } //100 cookies.sqlite
		$a_81_3 = {50 61 73 73 77 6f 72 64 73 2e 74 78 74 } //100 Passwords.txt
		$a_81_4 = {53 63 72 65 65 6e 2e 6a 70 67 } //100 Screen.jpg
		$a_81_5 = {56 69 76 61 6c 64 69 } //1 Vivaldi
		$a_81_6 = {54 6f 72 63 68 } //1 Torch
		$a_81_7 = {62 72 61 76 65 } //1 brave
		$a_81_8 = {53 6c 69 6d 6a 65 74 } //1 Slimjet
		$a_81_9 = {43 65 6e 74 42 72 6f 77 73 65 72 } //1 CentBrowser
		$a_81_10 = {43 6f 6d 6f 64 6f } //1 Comodo
		$a_81_11 = {43 6f 63 43 6f 63 } //1 CocCoc
		$a_81_12 = {47 6f 6f 67 6c 65 } //1 Google
		$a_81_13 = {33 36 30 43 68 72 6f 6d 65 } //1 360Chrome
		$a_81_14 = {4f 70 65 72 61 } //1 Opera
		$a_81_15 = {43 68 72 6f 6d 69 75 6d } //1 Chromium
	condition:
		((#a_81_0  & 1)*100+(#a_81_1  & 1)*100+(#a_81_2  & 1)*100+(#a_81_3  & 1)*100+(#a_81_4  & 1)*100+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1+(#a_81_15  & 1)*1) >=403
 
}