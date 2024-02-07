
rule TrojanDownloader_Win32_Delf_ZSA{
	meta:
		description = "TrojanDownloader:Win32/Delf.ZSA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 78 7a 31 39 2e 63 6f 6d } //01 00  .xz19.com
		$a_03_1 = {63 74 66 6d 6f 6e 5f 90 01 15 71 72 6e 5f 90 01 0c 6b 75 6f 64 6f 75 73 65 74 75 70 33 38 5f 90 00 } //01 00 
		$a_03_2 = {43 6e 49 45 2e 74 6d 70 90 01 0c 63 6e 2e 74 6d 70 90 01 0a 63 6e 2e 65 78 65 90 01 02 6c 6d 30 32 90 01 04 6d 79 69 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}