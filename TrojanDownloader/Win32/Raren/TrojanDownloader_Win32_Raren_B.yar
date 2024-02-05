
rule TrojanDownloader_Win32_Raren_B{
	meta:
		description = "TrojanDownloader:Win32/Raren.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {b0 65 b1 53 c6 44 24 08 41 c6 44 24 09 64 c6 44 24 0a 76 } //01 00 
		$a_00_1 = {7b 61 62 63 2d 5f 2d 63 62 61 7d } //00 00 
	condition:
		any of ($a_*)
 
}