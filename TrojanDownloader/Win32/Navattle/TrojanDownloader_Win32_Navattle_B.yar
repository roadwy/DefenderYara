
rule TrojanDownloader_Win32_Navattle_B{
	meta:
		description = "TrojanDownloader:Win32/Navattle.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 4d 53 76 63 48 6f 73 74 2e 65 78 65 00 } //01 00 
		$a_00_1 = {5c 74 73 6d 62 2e 62 61 74 00 } //01 00 
		$a_00_2 = {5c 74 65 73 74 2e 64 61 74 00 } //01 00 
		$a_00_3 = {41 68 6e 4c 61 62 20 56 33 4c 69 74 65 20 55 70 64 61 74 65 20 50 72 6f 63 65 73 73 00 } //01 00 
		$a_01_4 = {b3 0a f6 eb 02 41 ff f6 eb 02 01 83 c1 03 04 30 88 04 16 8a 41 fe 46 84 c0 75 e5 } //00 00 
	condition:
		any of ($a_*)
 
}