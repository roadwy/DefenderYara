
rule TrojanDownloader_Win32_Grameyoon_B{
	meta:
		description = "TrojanDownloader:Win32/Grameyoon.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 6f 6d 6f 63 65 6c 6c 2e 63 6f 6d 2f 6c 6f 67 2f 69 6e 73 74 61 6c 6c 2e 70 68 70 3f 6d 61 63 3d 00 } //01 00 
		$a_01_1 = {77 69 6e 20 6d 61 6e 61 67 65 72 20 57 69 6e 64 6f 77 00 } //01 00 
		$a_01_2 = {5b 36 65 36 46 34 34 37 34 5d 00 00 26 63 6f 64 65 3d 30 30 30 33 00 } //01 00 
		$a_01_3 = {68 61 6e 75 73 00 77 69 6e 73 74 61 30 5c 64 65 66 61 75 6c 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}