
rule Worm_Win32_Silly_P2P_gen_A{
	meta:
		description = "Worm:Win32/Silly_P2P.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {75 17 c7 85 90 01 02 ff ff 01 00 00 00 68 98 3a 00 00 ff 15 90 01 03 00 eb 02 eb 02 eb 90 01 01 6a 07 8d 85 90 01 02 ff ff 50 ff 15 90 01 03 00 83 bd 90 01 02 ff ff 00 74 05 90 00 } //02 00 
		$a_03_1 = {83 7d 0c 07 75 3b 6a 3f 68 90 01 04 8d 85 90 01 02 ff ff 50 e8 90 01 02 00 00 83 c4 0c ff 75 10 8d 85 90 01 02 ff ff 50 68 90 01 04 68 ff 01 00 00 90 00 } //01 00 
		$a_01_2 = {99 6a 0a 59 f7 f9 52 } //01 00 
		$a_01_3 = {77 65 62 73 69 74 65 3d 31 } //01 00 
		$a_01_4 = {6b 61 7a 61 61 5c 6d 79 20 73 68 61 72 65 64 20 66 6f 6c 64 65 72 } //01 00 
	condition:
		any of ($a_*)
 
}