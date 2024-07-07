
rule Trojan_BAT_IRCBot_EA_MTB{
	meta:
		description = "Trojan:BAT/IRCBot.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {4e 00 54 00 42 00 6f 00 74 00 2e 00 65 00 78 00 65 00 } //1 NTBot.exe
		$a_01_1 = {43 6f 6e 66 75 73 65 72 45 78 20 76 31 2e 30 2e 30 } //1 ConfuserEx v1.0.0
		$a_01_2 = {47 65 74 46 69 6c 65 73 } //1 GetFiles
		$a_01_3 = {53 74 61 72 74 73 57 69 74 68 } //1 StartsWith
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_5 = {57 72 69 74 65 41 6c 6c 42 79 74 65 73 } //1 WriteAllBytes
		$a_01_6 = {67 65 74 5f 43 6c 69 65 6e 74 } //1 get_Client
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}