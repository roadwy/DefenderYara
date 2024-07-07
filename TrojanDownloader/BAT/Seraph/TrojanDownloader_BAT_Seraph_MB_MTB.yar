
rule TrojanDownloader_BAT_Seraph_MB_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_03_0 = {1f 0d 6a 59 13 05 90 0a 1f 00 09 69 8d 90 01 03 01 25 17 73 90 01 03 0a 13 04 06 6f 90 01 03 0a 90 02 08 07 06 11 04 11 05 09 6f 90 01 03 06 2a 90 00 } //1
		$a_01_1 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 CheckRemoteDebuggerPresent
		$a_01_2 = {49 73 4c 6f 67 67 69 6e 67 } //1 IsLogging
		$a_01_3 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_5 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_6 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_7 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 44 00 61 00 74 00 61 00 } //1 DownloadData
		$a_01_8 = {44 65 62 75 67 67 65 72 } //1 Debugger
		$a_01_9 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_10 = {73 65 74 5f 4b 65 79 } //1 set_Key
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}