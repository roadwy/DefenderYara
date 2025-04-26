
rule Trojan_Win32_Downloader_RPH_MTB{
	meta:
		description = "Trojan:Win32/Downloader.RPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 } //1 cdn.discordapp.com
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_2 = {76 00 62 00 73 00 2e 00 65 00 78 00 65 00 } //1 vbs.exe
		$a_01_3 = {52 00 75 00 6e 00 50 00 45 00 2e 00 52 00 75 00 6e 00 50 00 45 00 } //1 RunPE.RunPE
		$a_01_4 = {52 00 75 00 6e 00 50 00 45 00 2e 00 64 00 6c 00 6c 00 } //1 RunPE.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Downloader_RPH_MTB_2{
	meta:
		description = "Trojan:Win32/Downloader.RPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {6b 00 61 00 6b 00 6f 00 73 00 69 00 64 00 6f 00 62 00 72 00 6f 00 73 00 61 00 6d 00 2e 00 67 00 71 00 } //1 kakosidobrosam.gq
		$a_01_1 = {43 72 65 61 74 65 } //1 Create
		$a_01_2 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //1 HttpWebRequest
		$a_01_3 = {47 65 74 52 65 73 70 6f 6e 73 65 } //1 GetResponse
		$a_01_4 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_5 = {53 74 72 65 61 6d 52 65 61 64 65 72 } //1 StreamReader
		$a_01_6 = {54 65 78 74 52 65 61 64 65 72 } //1 TextReader
		$a_01_7 = {4c 61 7a 79 49 6e 69 74 69 61 6c 69 7a 65 72 } //1 LazyInitializer
		$a_01_8 = {4c 6f 61 64 4c 69 62 72 61 72 79 } //1 LoadLibrary
		$a_01_9 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}