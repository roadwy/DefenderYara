
rule TrojanDownloader_Win32_Banload_AWQ{
	meta:
		description = "TrojanDownloader:Win32/Banload.AWQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_03_0 = {72 6f 61 6d 69 6e 67 [0-10] 2e 74 78 74 [0-10] 2e 65 78 65 [0-10] 2e (58 78 58|70 6e 67) } //1
		$a_01_1 = {00 63 68 61 76 65 00 } //1
		$a_01_2 = {00 32 41 46 31 30 45 45 33 32 32 33 39 } //1
		$a_01_3 = {00 36 45 42 35 34 32 44 37 33 45 31 44 } //1
		$a_03_4 = {33 db 8a 5c 38 ff 33 9d ?? ?? ff ff 3b 9d f0 fe ff ff 7f 0e 81 c3 ff 00 00 00 2b 9d ?? ?? ff ff eb 06 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=3
 
}