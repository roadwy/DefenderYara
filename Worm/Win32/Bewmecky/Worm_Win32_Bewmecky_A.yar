
rule Worm_Win32_Bewmecky_A{
	meta:
		description = "Worm:Win32/Bewmecky.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 08 88 0a 83 c0 01 83 c2 01 84 c9 75 f2 e9 90 01 04 83 ff 02 75 28 90 00 } //01 00 
		$a_03_1 = {8a 14 19 83 c3 01 80 fa 40 74 08 81 fb f4 01 00 00 7c ed 33 c0 33 f6 85 db bf 01 00 00 00 0f 8e 90 01 02 00 00 80 3c 31 23 90 00 } //01 00 
		$a_01_2 = {5b 61 75 74 6f 72 75 6e 5d } //01 00  [autorun]
		$a_01_3 = {5c 72 65 63 79 63 6c 65 72 } //00 00  \recycler
	condition:
		any of ($a_*)
 
}