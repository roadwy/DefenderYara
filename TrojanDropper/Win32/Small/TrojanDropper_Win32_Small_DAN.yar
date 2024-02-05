
rule TrojanDropper_Win32_Small_DAN{
	meta:
		description = "TrojanDropper:Win32/Small.DAN,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 04 01 00 00 8d 85 30 fd ff ff 50 ff 15 6c 10 40 00 68 e0 10 40 00 8d 8d 30 fd ff ff 51 ff 15 68 10 40 00 6a 90 01 01 68 90 01 03 00 68 00 90 01 01 00 00 68 90 01 03 00 8d 95 30 fd ff ff 52 e8 f4 fc ff ff 83 c4 14 8d 85 30 fd ff ff 50 e8 e5 fe ff ff 83 c4 04 68 60 ea 00 00 ff 15 64 10 40 00 83 7d dc 01 0f 85 3a 01 00 00 e8 88 03 00 00 90 00 } //01 00 
		$a_03_1 = {68 04 01 00 00 8d 8d 30 fd ff ff 51 ff 15 6c 10 40 00 68 f0 10 40 00 8d 95 30 fd ff ff 52 ff 15 68 10 40 00 6a 90 01 01 68 90 01 03 00 68 00 90 01 01 00 00 68 90 01 03 00 8d 85 30 fd ff ff 50 e8 87 fc ff ff 90 00 } //01 00 
		$a_00_2 = {77 69 6e 6d 73 64 6e 2e 65 78 65 } //01 00 
		$a_00_3 = {64 6c 6c 63 61 63 68 65 5c 66 75 75 72 6f 64 2e 73 79 73 } //01 00 
		$a_00_4 = {64 72 69 76 65 72 73 5c 62 65 65 70 2e 73 79 73 } //01 00 
		$a_00_5 = {64 6c 6c 63 61 63 68 65 5c 62 65 65 70 2e 73 79 73 } //00 00 
	condition:
		any of ($a_*)
 
}