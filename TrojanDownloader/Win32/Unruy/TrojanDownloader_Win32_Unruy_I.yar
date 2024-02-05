
rule TrojanDownloader_Win32_Unruy_I{
	meta:
		description = "TrojanDownloader:Win32/Unruy.I,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 44 6a 46 6a 30 6a 34 90 02 2f 81 c4 a0 00 00 00 8d 90 02 09 68 03 00 1f 00 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}