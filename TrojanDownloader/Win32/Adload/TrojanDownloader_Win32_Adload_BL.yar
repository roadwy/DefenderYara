
rule TrojanDownloader_Win32_Adload_BL{
	meta:
		description = "TrojanDownloader:Win32/Adload.BL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 65 64 69 61 75 70 64 74 2e 65 78 65 00 64 6f 77 6e 6c 6f 61 64 00 6d 65 64 69 61 63 68 63 6b 2e 65 78 65 00 } //01 00 
		$a_01_1 = {6d 65 64 69 61 6d 65 64 69 61 6c 74 64 2e 69 6e 2f 6d 65 64 69 61 } //00 00  mediamedialtd.in/media
	condition:
		any of ($a_*)
 
}