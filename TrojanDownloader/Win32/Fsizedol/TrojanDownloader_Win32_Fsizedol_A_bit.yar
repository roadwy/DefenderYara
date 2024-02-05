
rule TrojanDownloader_Win32_Fsizedol_A_bit{
	meta:
		description = "TrojanDownloader:Win32/Fsizedol.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00 
		$a_01_1 = {48 6f 73 74 3a 20 68 65 6c 6c 6f 2e 70 68 70 } //01 00 
		$a_01_2 = {5c 6c 61 73 74 2e 65 78 65 } //01 00 
		$a_01_3 = {64 61 74 61 3d 65 79 4a 31 64 57 6c 6b 49 6a 6f 69 49 69 77 69 59 6e 56 70 62 47 51 69 4f 6a 59 73 49 6d 39 7a 49 6a 6f 69 56 32 6c 75 56 32 6c 75 5a 47 39 33 63 79 49 73 49 6d 35 68 64 43 49 36 4d 48 30 3d } //00 00 
		$a_00_4 = {5d 04 00 } //00 1a 
	condition:
		any of ($a_*)
 
}