
rule TrojanDownloader_Win32_Banload_YK{
	meta:
		description = "TrojanDownloader:Win32/Banload.YK,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {61 76 67 75 69 78 2e 65 78 65 00 } //1
		$a_00_1 = {64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 32 00 } //1
		$a_00_2 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 22 20 2f 76 20 61 76 67 75 69 78 } //1 CurrentVersion\Run" /v avguix
		$a_01_3 = {83 7b 58 00 74 06 83 7b 5c 00 75 0c b2 03 8b c3 e8 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}