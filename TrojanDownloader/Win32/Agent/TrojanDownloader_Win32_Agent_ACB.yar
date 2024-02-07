
rule TrojanDownloader_Win32_Agent_ACB{
	meta:
		description = "TrojanDownloader:Win32/Agent.ACB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 09 00 00 0a 00 "
		
	strings :
		$a_01_0 = {43 6f 4d 61 72 73 68 61 6c 49 6e 74 65 72 54 68 72 65 61 64 49 6e 74 65 72 66 61 63 65 49 6e 53 74 72 65 61 6d } //0a 00  CoMarshalInterThreadInterfaceInStream
		$a_01_1 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //0a 00  InternetOpenUrlA
		$a_01_2 = {25 73 3f 63 6d 70 3d 25 73 26 75 69 64 3d 25 73 26 67 75 69 64 3d 25 73 26 61 66 66 69 64 3d 25 73 26 6e 69 64 3d 61 64 26 6c 69 64 3d 25 73 } //01 00  %s?cmp=%s&uid=%s&guid=%s&affid=%s&nid=ad&lid=%s
		$a_01_3 = {68 74 74 70 3a 2f 2f 36 35 2e 32 34 33 2e 31 30 33 2e } //01 00  http://65.243.103.
		$a_01_4 = {68 74 74 70 3a 2f 2f 38 39 2e 31 38 38 2e 31 36 2e } //01 00  http://89.188.16.
		$a_01_5 = {4d 4a 55 41 4e } //01 00  MJUAN
		$a_01_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4d 53 20 4a 75 61 6e } //01 00  Software\Microsoft\MS Juan
		$a_01_7 = {4a 00 75 00 61 00 6e 00 5f 00 54 00 72 00 61 00 63 00 6b 00 69 00 6e 00 67 00 5f 00 4d 00 75 00 74 00 65 00 78 00 } //01 00  Juan_Tracking_Mutex
		$a_01_8 = {4d 75 74 65 78 5f 4a 75 61 6e 5f 4c 43 } //00 00  Mutex_Juan_LC
	condition:
		any of ($a_*)
 
}