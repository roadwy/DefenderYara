
rule Trojan_Win32_ClipBanker_AJ_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 4b 65 79 62 6f 61 72 64 4c 61 79 6f 75 74 4c 69 73 74 } //2 GetKeyboardLayoutList
		$a_01_1 = {49 6e 74 65 72 6e 65 74 43 72 61 63 6b 55 72 6c 41 } //2 InternetCrackUrlA
		$a_01_2 = {50 61 73 73 77 6f 72 64 73 4c 69 73 74 2e 74 78 74 } //2 PasswordsList.txt
		$a_01_3 = {73 63 72 2e 6a 70 67 } //2 scr.jpg
		$a_01_4 = {53 79 73 74 65 6d 2e 74 78 74 } //2 System.txt
		$a_01_5 = {69 70 2e 74 78 74 } //2 ip.txt
		$a_01_6 = {45 00 6c 00 65 00 63 00 74 00 72 00 75 00 6d 00 5c 00 77 00 61 00 6c 00 6c 00 65 00 74 00 73 00 } //2 Electrum\wallets
		$a_01_7 = {73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 74 00 69 00 6d 00 65 00 6f 00 75 00 74 00 2e 00 65 00 78 00 65 00 20 00 33 00 20 00 26 00 20 00 64 00 65 00 6c 00 } //2 system32\timeout.exe 3 & del
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2) >=16
 
}