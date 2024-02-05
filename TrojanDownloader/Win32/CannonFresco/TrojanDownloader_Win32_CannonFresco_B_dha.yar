
rule TrojanDownloader_Win32_CannonFresco_B_dha{
	meta:
		description = "TrojanDownloader:Win32/CannonFresco.B!dha,SIGNATURE_TYPE_CMDHSTR_EXT,63 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 6b 64 69 72 20 25 61 70 70 64 61 74 61 25 5c 73 79 73 74 65 6d 55 70 64 61 74 69 6e 67 20 26 20 70 6f 77 65 72 73 68 65 6c 6c 20 2d 77 20 31 20 2d 6e 6f 6c 6f 67 6f 20 2d 65 63 } //00 00 
	condition:
		any of ($a_*)
 
}