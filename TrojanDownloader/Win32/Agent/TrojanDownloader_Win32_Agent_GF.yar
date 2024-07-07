
rule TrojanDownloader_Win32_Agent_GF{
	meta:
		description = "TrojanDownloader:Win32/Agent.GF,SIGNATURE_TYPE_PEHSTR,33 00 33 00 09 00 00 "
		
	strings :
		$a_01_0 = {31 39 32 2e 31 36 38 2e 30 2e 31 30 32 } //10 192.168.0.102
		$a_01_1 = {32 30 38 2e 36 36 2e 31 39 34 2e 32 31 35 } //10 208.66.194.215
		$a_01_2 = {68 74 74 70 3a 2f 2f 25 73 2f 4d 61 69 6c 2f 25 73 } //10 http://%s/Mail/%s
		$a_01_3 = {6a 61 76 61 73 63 72 69 70 74 3a 6f 6e 53 75 62 6d 69 74 54 6f 6f 6c 62 61 72 49 74 65 6d 43 6c 69 63 6b 65 64 28 } //10 javascript:onSubmitToolbarItemClicked(
		$a_01_4 = {5a 3a 5c 4e 65 77 50 72 6f 6a 65 63 74 73 5c 68 6f 74 73 65 6e 64 5c 52 65 6c 65 61 73 65 2d 57 69 6e 33 32 5c 68 6f 74 73 65 6e 64 2e 70 64 62 } //10 Z:\NewProjects\hotsend\Release-Win32\hotsend.pdb
		$a_01_5 = {58 4f 52 61 72 72 61 79 73 } //1 XORarrays
		$a_01_6 = {52 53 41 65 6e 63 72 79 70 74 } //1 RSAencrypt
		$a_01_7 = {70 61 72 73 65 52 53 41 4b 65 79 46 72 6f 6d 53 74 72 69 6e 67 } //1 parseRSAKeyFromString
		$a_01_8 = {57 53 63 72 69 70 74 2e 45 63 68 6f 28 45 6e 63 72 79 70 74 28 } //1 WScript.Echo(Encrypt(
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=51
 
}