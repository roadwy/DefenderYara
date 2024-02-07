
rule TrojanDownloader_Win32_Lacrec_A{
	meta:
		description = "TrojanDownloader:Win32/Lacrec.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {43 eb 8b 80 3d 90 01 04 01 75 4c 68 90 01 04 e8 90 00 } //02 00 
		$a_03_1 = {80 7c 18 ff 3b 75 45 8d 04 b5 90 01 04 50 8b cb 49 ba 01 00 00 00 90 00 } //01 00 
		$a_01_2 = {43 4f 43 4c 41 00 } //01 00  佃䱃A
		$a_01_3 = {52 65 67 43 6f 6d 33 32 00 } //00 00 
	condition:
		any of ($a_*)
 
}