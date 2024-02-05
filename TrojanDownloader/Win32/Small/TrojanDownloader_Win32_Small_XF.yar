
rule TrojanDownloader_Win32_Small_XF{
	meta:
		description = "TrojanDownloader:Win32/Small.XF,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {b9 64 61 74 22 ba 2c 55 70 64 89 90 01 14 c7 04 18 5c 73 79 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}