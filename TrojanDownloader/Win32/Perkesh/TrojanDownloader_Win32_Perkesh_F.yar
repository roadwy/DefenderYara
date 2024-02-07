
rule TrojanDownloader_Win32_Perkesh_F{
	meta:
		description = "TrojanDownloader:Win32/Perkesh.F,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {74 35 55 bd 90 01 04 6a 01 e8 90 01 04 6a 00 55 55 6a ff e8 90 01 04 8a c3 b1 90 01 01 2c 90 01 01 8b fe f6 e9 00 04 33 90 00 } //02 00 
		$a_03_1 = {68 78 e6 00 00 e8 90 01 04 46 3b 35 90 01 04 7c ed eb 10 6a 1e 90 00 } //01 00 
		$a_01_2 = {26 7a 3d 00 26 74 3d 00 } //01 00  稦=琦=
		$a_01_3 = {7e 25 78 2e 64 61 74 00 } //01 00 
		$a_01_4 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 00 00 25 73 25 64 00 } //00 00 
	condition:
		any of ($a_*)
 
}