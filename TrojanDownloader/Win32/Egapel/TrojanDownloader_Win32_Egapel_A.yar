
rule TrojanDownloader_Win32_Egapel_A{
	meta:
		description = "TrojanDownloader:Win32/Egapel.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f 3f 07 0b c7 45 } //01 00 
		$a_01_1 = {25 73 3f 6d 61 63 3d 25 73 26 76 65 72 3d 25 73 26 6f 73 3d 25 73 } //01 00 
		$a_01_2 = {80 f9 56 75 08 8a 10 40 80 fa 56 74 f8 } //00 00 
	condition:
		any of ($a_*)
 
}