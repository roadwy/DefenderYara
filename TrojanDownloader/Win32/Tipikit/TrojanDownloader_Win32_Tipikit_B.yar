
rule TrojanDownloader_Win32_Tipikit_B{
	meta:
		description = "TrojanDownloader:Win32/Tipikit.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {2d 41 75 07 e8 90 01 02 ff ff eb 33 e8 90 01 02 ff ff 83 3d 90 01 02 40 00 00 75 00 eb 1a 68 90 01 02 00 00 90 09 07 00 66 81 3d 90 01 02 40 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}