
rule TrojanDownloader_Win32_Renos_AT{
	meta:
		description = "TrojanDownloader:Win32/Renos.AT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {20 54 68 69 73 20 28 29 20 70 72 6f 67 72 61 6d 20 69 6e 73 74 61 6c 6c 20 } //1  This () program install 
		$a_01_1 = {00 59 6f 75 20 63 61 6e 20 64 6f 77 6e 6c 6f 61 64 20 6e 65 77 20 76 65 72 73 69 6f 6e 2e 00 } //1
		$a_01_2 = {8b 75 08 80 3e 00 74 05 30 06 46 eb f6 c9 c2 08 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}