
rule Trojan_BAT_Dllinject_CA_MTB{
	meta:
		description = "Trojan:BAT/Dllinject.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 61 70 69 2e 74 68 75 6e 64 65 72 6d 6f 64 73 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 73 2f 45 61 73 79 45 78 70 6c 6f 69 74 73 2e 64 6c 6c } //1 http://api.thundermods.com/downloads/EasyExploits.dll
		$a_81_1 = {68 74 74 70 73 3a 2f 2f 72 61 77 2e 67 69 74 68 75 62 75 73 65 72 63 6f 6e 74 65 6e 74 2e 63 6f 6d 2f 52 61 6e 64 6f 6d 41 64 61 6d 59 54 2f 44 61 72 6b 48 75 62 2f 6d 61 73 74 65 72 2f 49 6e 69 74 } //1 https://raw.githubusercontent.com/RandomAdamYT/DarkHub/master/Init
		$a_81_2 = {68 74 74 70 73 3a 2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 2f 69 6d 45 41 51 58 37 71 } //1 https://pastebin.com/raw/imEAQX7q
		$a_81_3 = {77 65 61 72 65 64 65 76 73 2e 6e 65 74 } //1 wearedevs.net
		$a_81_4 = {48 54 54 50 44 65 62 75 67 67 65 72 50 72 6f } //1 HTTPDebuggerPro
		$a_81_5 = {48 61 63 6b 65 72 } //1 Hacker
		$a_81_6 = {53 6b 69 73 70 6c 6f 69 74 2e 64 6c 6c } //1 Skisploit.dll
		$a_81_7 = {68 74 74 70 3a 2f 2f 61 70 69 2e 74 68 75 6e 64 65 72 6d 6f 64 73 2e 63 6f 6d 2f 75 70 64 61 74 65 6d 65 73 73 61 67 65 2e 74 78 74 } //1 http://api.thundermods.com/updatemessage.txt
		$a_81_8 = {49 6e 6a 65 63 74 65 64 } //1 Injected
		$a_81_9 = {44 6f 77 6e 6c 6f 61 64 20 69 74 20 66 72 6f 6d 20 68 74 74 70 3a 2f 2f 62 69 74 2e 6c 79 2f 63 72 65 74 72 69 62 75 74 69 6f 6e 73 } //1 Download it from http://bit.ly/cretributions
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}