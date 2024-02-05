
rule TrojanDownloader_Win32_Matcash_H{
	meta:
		description = "TrojanDownloader:Win32/Matcash.H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 6c 00 00 73 2e 00 00 2e 77 72 } //01 00 
		$a_01_1 = {42 c9 21 d3 f2 b3 12 22 02 ab 08 66 00 } //00 00 
	condition:
		any of ($a_*)
 
}