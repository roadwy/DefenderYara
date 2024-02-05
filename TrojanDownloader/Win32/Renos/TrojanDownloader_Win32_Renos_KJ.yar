
rule TrojanDownloader_Win32_Renos_KJ{
	meta:
		description = "TrojanDownloader:Win32/Renos.KJ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 00 14 2d 00 90 17 03 05 06 01 ff 75 90 01 01 ff 74 24 90 01 01 56 90 03 05 02 ff 15 90 01 04 ff d0 85 c0 90 03 02 01 0f 84 74 90 00 } //01 00 
		$a_01_1 = {44 6c 6c 44 65 66 69 6e 65 00 44 6c 6c 52 65 67 } //01 00 
		$a_03_2 = {40 3d 00 01 00 00 90 01 01 90 03 01 01 f1 f4 90 00 } //01 00 
		$a_03_3 = {10 68 ff ff 90 01 02 68 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}