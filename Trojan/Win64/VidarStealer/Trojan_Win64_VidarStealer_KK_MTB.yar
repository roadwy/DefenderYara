
rule Trojan_Win64_VidarStealer_KK_MTB{
	meta:
		description = "Trojan:Win64/VidarStealer.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 0a 00 00 "
		
	strings :
		$a_01_0 = {42 72 6f 77 73 65 72 20 4c 69 73 74 } //9 Browser List
		$a_01_1 = {43 68 72 6f 6d 69 75 6d 20 50 6c 75 67 69 6e 73 } //8 Chromium Plugins
		$a_01_2 = {46 69 72 65 66 6f 78 20 50 6c 75 67 69 6e 73 } //7 Firefox Plugins
		$a_01_3 = {57 61 6c 6c 65 74 20 52 75 6c 65 73 } //6 Wallet Rules
		$a_01_4 = {46 69 6c 65 20 47 72 61 62 62 65 72 20 52 75 6c 65 73 } //5 File Grabber Rules
		$a_01_5 = {4c 6f 61 64 65 72 20 54 61 73 6b 73 } //4 Loader Tasks
		$a_01_6 = {63 68 72 6f 6d 65 } //3 chrome
		$a_01_7 = {66 69 72 65 66 6f 78 } //2 firefox
		$a_01_8 = {6f 70 65 72 61 } //1 opera
		$a_01_9 = {48 ff c0 88 17 83 e9 01 8a 10 48 8d 7f 01 } //5
	condition:
		((#a_01_0  & 1)*9+(#a_01_1  & 1)*8+(#a_01_2  & 1)*7+(#a_01_3  & 1)*6+(#a_01_4  & 1)*5+(#a_01_5  & 1)*4+(#a_01_6  & 1)*3+(#a_01_7  & 1)*2+(#a_01_8  & 1)*1+(#a_01_9  & 1)*5) >=50
 
}