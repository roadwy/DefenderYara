
rule PWS_Win32_Tibia_Y{
	meta:
		description = "PWS:Win32/Tibia.Y,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {79 73 69 6f 6c 6f 67 67 65 72 2e 79 6f 79 6f 2e 70 6c 2f 61 64 64 72 65 73 73 74 69 62 69 61 2e 74 78 74 00 ff ff ff ff 2c 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e 72 79 73 69 6f 6c 6f 67 67 65 72 2e 79 6f 79 6f 2e 70 6c 2f 69 74 65 6d 74 69 62 69 61 2e 74 78 74 00 00 00 00 ff ff ff ff 2a 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e 72 79 73 69 6f 6c 6f 67 67 65 72 2e 79 6f 79 6f 2e 70 6c 2f 69 64 74 69 62 69 61 2e 74 78 74 00 00 ff ff ff ff 25 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e 72 79 73 69 6f 6c 6f 67 67 65 72 2e 79 6f 79 6f 2e 70 6c 2f 67 67 2e 74 78 74 00 00 00 } //01 00 
		$a_00_1 = {54 69 62 69 61 43 6c 69 65 6e 74 } //01 00  TibiaClient
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //00 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		any of ($a_*)
 
}