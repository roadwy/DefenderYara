
rule TrojanDownloader_Win32_Delf_NK{
	meta:
		description = "TrojanDownloader:Win32/Delf.NK,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {36 30 2e 31 39 31 2e 32 35 34 2e 32 35 33 } //1 60.191.254.253
		$a_01_1 = {73 74 64 33 33 32 32 2e 63 6f 6d } //1 std3322.com
		$a_01_2 = {67 6c 61 64 31 32 33 2e 63 6f 6d } //1 glad123.com
		$a_01_3 = {63 6c 75 64 33 33 2e 63 6f 6d } //1 clud33.com
		$a_01_4 = {5c 73 65 74 6f 70 33 30 31 30 2e 65 78 65 } //10 \setop3010.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*10) >=10
 
}
rule TrojanDownloader_Win32_Delf_NK_2{
	meta:
		description = "TrojanDownloader:Win32/Delf.NK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 00 69 00 79 00 61 00 79 00 75 00 6d 00 6e 00 65 00 } //1 aiyayumne
		$a_01_1 = {2e 00 64 00 6f 00 77 00 6e 00 78 00 69 00 61 00 2e 00 6e 00 65 00 74 00 } //1 .downxia.net
		$a_03_2 = {8b 14 98 b8 90 01 04 e8 90 01 04 85 c0 7f 16 a1 90 01 04 8b 14 98 b8 90 01 04 e8 90 01 04 85 c0 7e 6b 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}