
rule TrojanDownloader_Win32_Delf_CN{
	meta:
		description = "TrojanDownloader:Win32/Delf.CN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 00 90 05 03 01 00 ff ff ff ff 90 01 01 00 00 00 68 74 74 70 3a 2f 2f 90 02 30 2e 65 78 65 00 90 00 } //01 00 
		$a_00_1 = {c3 64 6f 77 6e 6c 6f 61 64 00 } //00 00 
	condition:
		any of ($a_*)
 
}