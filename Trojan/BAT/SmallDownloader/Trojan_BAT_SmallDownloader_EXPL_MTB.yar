
rule Trojan_BAT_SmallDownloader_EXPL_MTB{
	meta:
		description = "Trojan:BAT/SmallDownloader.EXPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_81_0 = {53 65 74 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 45 78 74 65 6e 73 69 6f 6e 20 65 78 65 } //1 Set-MpPreference -ExclusionExtension exe
		$a_81_1 = {53 74 61 72 74 2d 53 6c 65 65 70 } //1 Start-Sleep
		$a_81_2 = {63 75 72 6c 2e 65 78 65 } //1 curl.exe
		$a_81_3 = {45 78 70 6c 6f 69 74 } //1 Exploit
		$a_81_4 = {57 65 62 53 65 72 76 69 63 65 73 } //1 WebServices
		$a_81_5 = {67 65 74 5f 45 78 65 63 75 74 61 62 6c 65 50 61 74 68 } //1 get_ExecutablePath
		$a_81_6 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 set_UseShellExecute
		$a_81_7 = {43 6f 6e 63 61 74 } //1 Concat
		$a_81_8 = {70 6f 77 65 72 73 68 65 6c 6c } //1 powershell
		$a_81_9 = {2f 6b 20 53 54 41 52 54 } //1 /k START
		$a_81_10 = {20 26 20 45 58 49 54 } //1  & EXIT
		$a_81_11 = {73 65 74 5f 41 72 67 75 6d 65 6e 74 73 } //1 set_Arguments
		$a_81_12 = {53 6f 61 70 48 74 74 70 43 6c 69 65 6e 74 50 72 6f 74 6f 63 6f 6c } //1 SoapHttpClientProtocol
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1) >=13
 
}
rule Trojan_BAT_SmallDownloader_EXPL_MTB_2{
	meta:
		description = "Trojan:BAT/SmallDownloader.EXPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_81_0 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_81_1 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_2 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //1 DownloadString
		$a_81_3 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //1 GetFolderPath
		$a_81_4 = {67 65 74 5f 4e 65 74 77 6f 72 6b } //1 get_Network
		$a_81_5 = {54 6f 53 74 72 69 6e 67 } //1 ToString
		$a_81_6 = {53 65 72 76 65 72 43 6f 6d 70 75 74 65 72 } //1 ServerComputer
		$a_81_7 = {68 74 74 70 73 3a 2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 2f } //1 https://pastebin.com/raw/
		$a_00_8 = {24 37 39 41 36 36 42 33 33 2d 37 38 45 46 2d 34 33 45 35 2d 38 31 41 38 2d 36 33 35 36 33 31 30 39 38 36 33 39 } //1 $79A66B33-78EF-43E5-81A8-635631098639
		$a_81_9 = {53 6f 61 70 48 74 74 70 43 6c 69 65 6e 74 50 72 6f 74 6f 63 6f 6c } //1 SoapHttpClientProtocol
		$a_81_10 = {53 70 65 63 69 61 6c 46 6f 6c 64 65 72 } //1 SpecialFolder
		$a_81_11 = {67 65 74 5f 57 65 62 53 65 72 76 69 63 65 73 } //1 get_WebServices
		$a_81_12 = {50 72 6f 63 65 73 73 } //1 Process
		$a_81_13 = {43 6f 6e 63 61 74 } //1 Concat
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_00_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1) >=14
 
}