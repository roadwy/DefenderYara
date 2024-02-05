
rule TrojanDownloader_Win32_Redosdru_F_bit{
	meta:
		description = "TrojanDownloader:Win32/Redosdru.F!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 08 32 ca 02 ca 88 08 40 4e } //01 00 
		$a_00_1 = {8a 14 02 8a 1c 2f 32 da 8b 54 24 1c 88 1c 2f 47 3b fa 72 90 } //01 00 
		$a_01_2 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 61 63 72 6b 5c 43 61 63 72 6b 2e 64 6c 6c } //01 00 
		$a_01_3 = {2f 53 79 73 74 65 6d 90 01 01 2e 64 6c 6c 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Redosdru_F_bit_2{
	meta:
		description = "TrojanDownloader:Win32/Redosdru.F!bit,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 14 02 8a 1c 2f 32 da 8b 54 24 1c 88 1c 2f 47 3b fa 72 90 } //01 00 
		$a_01_1 = {c6 44 24 20 4d c6 44 24 21 6f c6 44 24 22 7a 88 54 24 23 88 4c 24 26 c6 44 24 27 2f c6 44 24 28 34 } //00 00 
	condition:
		any of ($a_*)
 
}