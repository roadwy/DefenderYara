
rule TrojanDownloader_Win32_Hancitor_ZX{
	meta:
		description = "TrojanDownloader:Win32/Hancitor.ZX,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 64 00 "
		
	strings :
		$a_01_0 = {b8 01 00 00 00 6b c8 00 c6 81 00 50 ef 14 00 68 00 20 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}