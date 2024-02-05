
rule PWS_Win32_Dyzap_M{
	meta:
		description = "PWS:Win32/Dyzap.M,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 08 00 00 05 00 "
		
	strings :
		$a_01_0 = {0f b6 16 8a 8c 15 00 ff ff ff 88 0e 48 46 85 c0 7f } //05 00 
		$a_00_1 = {47 00 6f 00 6f 00 67 00 6c 00 65 00 20 00 55 00 70 00 64 00 61 00 74 00 65 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 } //01 00 
		$a_80_2 = {5a 77 51 75 65 75 65 41 70 63 54 68 72 65 61 64 } //ZwQueueApcThread  01 00 
		$a_00_3 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //01 00 
		$a_01_4 = {89 4c 24 14 39 51 44 0f 85 fe 00 00 00 89 7c 24 1c 39 79 04 0f 86 f1 00 00 00 8d 81 dc 00 00 00 89 44 24 20 eb 07 } //01 00 
		$a_01_5 = {89 4c 24 14 39 51 44 0f 85 ff 00 00 00 83 79 04 00 c7 44 24 1c 00 00 00 00 0f 86 ed 00 00 00 8d 81 dc 00 00 00 89 44 24 20 } //01 00 
		$a_01_6 = {39 51 44 0f 85 ff 00 00 00 83 79 04 00 c7 44 24 1c 00 00 00 00 0f 86 ed 00 00 00 8d 81 dc 00 00 00 89 44 24 20 } //01 00 
		$a_01_7 = {8b 4c 24 04 83 79 64 02 } //00 00 
		$a_00_8 = {80 10 00 00 a9 9e } //4a 06 
	condition:
		any of ($a_*)
 
}