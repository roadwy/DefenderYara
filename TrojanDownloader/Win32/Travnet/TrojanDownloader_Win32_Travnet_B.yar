
rule TrojanDownloader_Win32_Travnet_B{
	meta:
		description = "TrojanDownloader:Win32/Travnet.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 6e 65 74 6d 67 72 2e 6c 6e 6b } //01 00 
		$a_01_1 = {25 73 6e 65 74 6d 67 72 2e 65 78 65 } //01 00 
		$a_01_2 = {4e 54 2d 32 30 31 32 20 49 73 20 52 75 6e 6e 69 6e 67 21 } //01 00 
		$a_01_3 = {55 70 6c 6f 61 64 52 61 74 65 00 00 44 6f 77 6e 43 6d 64 54 69 6d 65 } //01 00 
		$a_01_4 = {25 73 70 65 72 66 32 30 31 32 2e 69 6e 69 } //00 00 
		$a_00_5 = {5d 04 00 } //00 25 
	condition:
		any of ($a_*)
 
}