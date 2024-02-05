
rule TrojanDownloader_Win32_Small_RS{
	meta:
		description = "TrojanDownloader:Win32/Small.RS,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 68 90 01 04 68 90 01 04 6a 00 e8 90 01 04 6a 01 6a 00 6a 00 68 90 01 04 68 90 01 04 6a 00 e8 90 00 } //01 00 
		$a_02_1 = {b8 01 00 00 00 60 6a 00 68 90 01 04 68 90 01 04 6a 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}