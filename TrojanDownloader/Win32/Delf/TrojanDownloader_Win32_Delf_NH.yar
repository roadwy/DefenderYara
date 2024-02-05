
rule TrojanDownloader_Win32_Delf_NH{
	meta:
		description = "TrojanDownloader:Win32/Delf.NH,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {53 8b d8 ba 90 01 04 b8 90 01 04 e8 90 01 04 84 c0 74 11 ba 90 01 04 b8 90 01 04 e8 90 01 04 84 c0 6a 01 6a 00 6a 00 68 90 01 04 68 90 01 04 8b c3 e8 90 01 04 50 e8 90 01 04 6a 01 6a 00 6a 00 68 90 01 04 68 90 01 04 8b c3 e8 90 01 04 50 e8 90 01 04 a1 90 01 04 8b 00 e8 90 01 04 5b c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}