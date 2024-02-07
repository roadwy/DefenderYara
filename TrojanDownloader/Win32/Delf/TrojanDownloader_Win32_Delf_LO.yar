
rule TrojanDownloader_Win32_Delf_LO{
	meta:
		description = "TrojanDownloader:Win32/Delf.LO,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 78 7a 31 39 2e 63 6f 6d } //01 00  .xz19.com
		$a_01_1 = {63 2e 37 74 6f 6f 74 2e 63 6e } //01 00  c.7toot.cn
		$a_03_2 = {63 6e 2e 74 6d 70 90 01 0a 63 6e 2e 65 78 65 90 01 02 6c 6d 30 32 90 01 04 6d 79 69 65 90 00 } //01 00 
		$a_03_3 = {25 64 00 00 64 6b 65 90 01 09 78 7a 7a 2f 90 01 18 63 74 66 6d 6f 6e 5f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}