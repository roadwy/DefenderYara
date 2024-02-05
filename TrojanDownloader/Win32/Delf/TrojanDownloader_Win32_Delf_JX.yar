
rule TrojanDownloader_Win32_Delf_JX{
	meta:
		description = "TrojanDownloader:Win32/Delf.JX,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 54 54 50 2f 31 2e 30 20 32 30 30 20 4f 4b } //01 00 
		$a_01_1 = {49 66 20 65 78 69 73 74 20 22 25 73 22 20 47 6f 74 6f 20 31 } //02 00 
		$a_01_2 = {47 74 66 78 69 6e 73 74 61 6c 6c } //02 00 
		$a_02_3 = {68 d0 07 00 00 e8 90 01 04 e8 90 01 04 68 cf 09 00 00 e8 90 01 04 6a 00 ff 36 68 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}