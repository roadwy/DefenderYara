
rule Trojan_Win32_CBotStealer_A{
	meta:
		description = "Trojan:Win32/CBotStealer.A,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 0b 00 00 "
		
	strings :
		$a_80_0 = {5c 5f 46 69 6c 65 73 5c 5f 49 6e 66 6f 72 6d 61 74 69 6f 6e 2e 74 78 74 } //\_Files\_Information.txt  1
		$a_80_1 = {4b 65 79 62 6f 61 72 64 20 4c 61 6e 67 75 61 67 65 73 3a 20 20 20 20 20 20 } //Keyboard Languages:        1
		$a_80_2 = {5c 5f 46 69 6c 65 73 5c 5f 41 6c 6c 43 6f 6f 6b 69 65 73 5f 6c 69 73 74 2e 74 78 74 } //\_Files\_AllCookies_list.txt  1
		$a_80_3 = {5c 66 69 6c 65 73 5f 5c 63 6f 6f 6b 69 65 73 2e 74 78 74 } //\files_\cookies.txt  1
		$a_80_4 = {5c 5f 46 69 6c 65 73 5c 5f 43 6f 6f 6b 69 65 73 5c 67 6f 6f 67 6c 65 5f 63 68 72 6f 6d 65 2e 74 78 74 } //\_Files\_Cookies\google_chrome.txt  1
		$a_80_5 = {5c 66 69 6c 65 73 5f 5c 63 6f 6f 6b 69 65 73 5c 67 6f 6f 67 6c 65 5f 63 68 72 6f 6d 65 5f 70 72 6f 66 69 6c 65 5f 32 2e 74 78 74 } //\files_\cookies\google_chrome_profile_2.txt  1
		$a_80_6 = {5c 66 69 6c 65 73 5f 5c 63 72 79 70 74 6f 63 75 72 72 65 6e 63 79 5c } //\files_\cryptocurrency\  1
		$a_80_7 = {5c 5f 46 69 6c 65 73 5c 5f 57 61 6c 6c 65 74 5c } //\_Files\_Wallet\  1
		$a_80_8 = {2e 73 71 6c 69 74 65 } //.sqlite  1
		$a_80_9 = {2e 6a 73 6f 6e } //.json  1
		$a_80_10 = {55 73 65 72 4e 61 6d 65 20 28 43 6f 6d 70 75 74 65 72 4e 61 6d 65 29 3a 20 25 77 53 } //UserName (ComputerName): %wS  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1) >=100
 
}