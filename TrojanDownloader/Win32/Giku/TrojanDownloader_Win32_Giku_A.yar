
rule TrojanDownloader_Win32_Giku_A{
	meta:
		description = "TrojanDownloader:Win32/Giku.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 63 68 69 6c 61 69 2e 63 6f 6d 2f 73 79 73 74 65 6d 2f 6c 69 62 72 61 72 69 65 73 2f 74 65 70 2e 74 78 74 00 } //1
		$a_01_1 = {47 45 54 20 2f 73 79 73 74 65 6d 2f 6c 69 62 72 61 72 69 65 73 2f 74 65 70 2e 74 78 74 20 48 54 54 50 2f 31 2e 30 } //1 GET /system/libraries/tep.txt HTTP/1.0
		$a_01_2 = {4c 44 31 35 45 39 46 45 38 32 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}