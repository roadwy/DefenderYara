
rule Worm_Win32_Sirmiras_A{
	meta:
		description = "Worm:Win32/Sirmiras.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 54 3a ff 0f b7 ce c1 e9 08 32 d1 88 54 38 ff 8b 04 24 0f b6 44 38 ff 66 03 f0 66 69 c6 6d ce 66 05 bf 58 8b f0 43 66 ff 4c 24 04 75 c5 } //02 00 
		$a_03_1 = {6a 00 6a 11 e8 90 01 02 ff ff 6a 00 6a 00 6a 00 6a 56 e8 90 01 02 ff ff 50 e8 90 01 02 ff ff 6a 00 6a 03 6a 2d 6a 11 e8 90 01 02 ff ff 6a 00 6a 00 6a 00 6a 0d 90 00 } //02 00 
		$a_01_2 = {3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 00 } //01 00 
		$a_01_3 = {70 72 69 6e 63 65 73 73 5f 73 72 69 72 61 73 6d 69 2e 7a 69 70 00 } //01 00 
		$a_01_4 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 72 65 61 6c 70 6c 61 79 65 72 2e 65 78 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}