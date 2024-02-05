
rule TrojanDownloader_Win32_Ocibt_B{
	meta:
		description = "TrojanDownloader:Win32/Ocibt.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {5c 77 69 6e 72 61 72 5c 69 63 6f 5c 74 61 6f 62 61 6f 2e 74 62 69 63 6f } //01 00 
		$a_01_1 = {68 74 74 70 3a 2f 2f 6e 73 69 73 2e 73 66 2e 6e 65 74 2f 4e 53 49 53 5f 45 72 72 6f 72 } //02 00 
		$a_01_2 = {3f 69 3d 74 62 69 63 6f 26 } //00 00 
	condition:
		any of ($a_*)
 
}