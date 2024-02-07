
rule TrojanDownloader_Win32_Cutwail_CE{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.CE,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {81 c6 ca 00 00 00 } //0a 00 
		$a_03_1 = {89 85 9c fe ff ff b9 90 03 04 04 80 1e 00 00 00 1f 00 00 90 00 } //0a 00 
		$a_01_2 = {89 07 47 47 47 47 e2 } //01 00 
		$a_00_3 = {4c 6f 61 64 49 6d 61 67 65 57 } //01 00  LoadImageW
		$a_00_4 = {47 65 74 4f 62 6a 65 63 74 41 } //00 00  GetObjectA
	condition:
		any of ($a_*)
 
}