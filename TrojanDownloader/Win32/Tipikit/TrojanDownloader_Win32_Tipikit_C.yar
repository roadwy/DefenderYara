
rule TrojanDownloader_Win32_Tipikit_C{
	meta:
		description = "TrojanDownloader:Win32/Tipikit.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2d 41 75 07 e8 90 01 02 ff ff eb 2a e8 90 01 02 ff ff eb 1a 68 60 ea 00 00 e8 90 01 02 00 00 e8 90 09 07 00 66 81 3d 90 01 02 40 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}