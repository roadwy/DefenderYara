
rule Backdoor_Win32_IRCBot_QR{
	meta:
		description = "Backdoor:Win32/IRCBot.QR,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0c 00 08 00 00 "
		
	strings :
		$a_00_0 = {5b 6d 61 69 6e 5d } //1 [main]
		$a_00_1 = {5b 73 63 61 6e 5d } //1 [scan]
		$a_00_2 = {5b 66 74 70 5d } //1 [ftp]
		$a_00_3 = {72 66 62 20 30 30 33 2e 30 30 38 } //2 rfb 003.008
		$a_00_4 = {54 52 65 67 43 72 61 70 } //2 TRegCrap
		$a_00_5 = {26 65 63 68 6f 20 62 79 65 } //2 &echo bye
		$a_01_6 = {4a 4f 49 4e 00 } //2
		$a_01_7 = {41 44 44 4e 45 57 7c } //2 ADDNEW|
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2) >=12
 
}