
rule TrojanDownloader_Win32_Delf_ZST{
	meta:
		description = "TrojanDownloader:Win32/Delf.ZST,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 2e 31 2e 65 61 73 74 66 6f 72 74 69 2e 63 6e 2f 64 36 2f } //1 f.1.eastforti.cn/d6/
		$a_03_1 = {00 73 2e 62 61 74 00 90 09 23 00 22 20 67 6f 74 6f 20 61 61 90 01 0b 64 65 6c 20 25 30 90 00 } //1
		$a_03_2 = {3f 74 74 6c 3d 90 01 0b 26 76 3d 90 01 09 26 73 3d 90 01 09 26 6e 3d 90 09 10 00 78 2e 61 73 70 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}