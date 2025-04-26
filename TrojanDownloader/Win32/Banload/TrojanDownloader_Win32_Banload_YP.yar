
rule TrojanDownloader_Win32_Banload_YP{
	meta:
		description = "TrojanDownloader:Win32/Banload.YP,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 32 73 68 61 72 65 64 2e 63 6f 6d 2f 66 69 6c 65 } //1 www.2shared.com/file
		$a_03_1 = {73 61 6e 74 61 ?? ?? 2e 64 6c 6c 00 } //1
		$a_03_2 = {74 61 70 65 ?? ?? 2e 65 78 65 00 } //1
		$a_01_3 = {45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 5c } //1 Explorer\Browser Helper Objects\
		$a_01_4 = {8b 55 f0 8b 83 5c 03 00 00 8b 80 20 02 00 00 8b 08 ff 51 74 b2 01 8b 83 48 03 00 00 e8 } //4
		$a_01_5 = {8b 83 5c 03 00 00 8b 10 ff 92 e0 00 00 00 8b 83 5c 03 00 00 8b 80 20 02 00 00 ba } //4
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*4+(#a_01_5  & 1)*4) >=9
 
}