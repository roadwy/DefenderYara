
rule TrojanDownloader_Win32_Banload_BED{
	meta:
		description = "TrojanDownloader:Win32/Banload.BED,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {00 7a 69 70 66 69 6c 65 90 02 05 26 90 02 05 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 50 72 6f 70 65 72 74 69 65 73 5c 64 61 74 61 2e 7a 69 70 00 90 00 } //1
		$a_01_1 = {00 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 50 72 6f 70 65 72 74 69 65 73 5c 75 70 64 63 6c 69 65 6e 74 2e 65 78 65 00 } //1
		$a_01_2 = {00 6f 70 65 6e 00 00 00 00 ff ff ff ff 0b 00 00 00 45 72 72 6f 72 20 39 30 30 34 35 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}