
rule TrojanDownloader_Win32_Garveep_E{
	meta:
		description = "TrojanDownloader:Win32/Garveep.E,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {8a 1c 37 32 d2 8d 4d ed c7 45 08 08 00 00 00 84 59 ff 74 04 0a 11 eb 06 8a 01 f6 d0 22 d0 41 41 ff 4d 08 75 ea 88 14 37 47 3b 7d fc 7c d2 } //03 00 
		$a_00_1 = {75 70 64 61 61 69 72 70 75 73 68 2e 69 67 6e 6f 72 65 6c 69 73 74 2e 63 6f 6d } //03 00 
		$a_00_2 = {63 25 34 64 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 2e 6a 70 67 } //03 00 
		$a_00_3 = {2d 7d 7a 69 6c 6c 61 5d 46 } //00 00 
	condition:
		any of ($a_*)
 
}