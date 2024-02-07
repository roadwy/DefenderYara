
rule TrojanDownloader_Win32_Banload_ART{
	meta:
		description = "TrojanDownloader:Win32/Banload.ART,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f bf c7 52 8b 11 50 52 c7 45 90 01 01 01 00 00 00 c7 45 90 01 01 02 00 00 00 ff 15 90 01 04 8b d0 8d 4d 90 00 } //01 00 
		$a_01_1 = {3a 00 5c 00 46 00 6f 00 6e 00 74 00 65 00 73 00 5c 00 45 00 76 00 78 00 31 00 33 00 5c 00 6c 00 6f 00 61 00 64 00 } //01 00  :\Fontes\Evx13\load
		$a_01_2 = {63 00 3a 00 5c 00 61 00 73 00 64 00 66 00 5c 00 73 00 64 00 66 00 2e 00 65 00 78 00 65 00 00 00 } //01 00 
		$a_03_3 = {6e 6f 6d 65 50 43 00 00 43 6f 6e 74 61 00 90 01 1a 5b 00 00 00 90 00 } //01 00 
		$a_01_4 = {5c 77 69 6e 68 74 74 70 2e 64 6c 6c 00 57 69 6e 48 74 74 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}