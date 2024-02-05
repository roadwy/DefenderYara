
rule TrojanDropper_Win32_Dinwod_B_bit{
	meta:
		description = "TrojanDropper:Win32/Dinwod.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 6d 63 79 2e 61 73 70 3f 61 74 3d 75 70 6d 26 73 31 33 3d } //01 00 
		$a_01_1 = {2f 6d 6f 6e 65 79 6f 75 74 2e 70 68 70 3f 6e 69 63 6b 6e 61 6d 65 3d } //01 00 
		$a_01_2 = {8b 01 ba ff fe fe 7e 03 d0 83 f0 ff 33 c2 83 c1 04 a9 00 01 01 81 74 e8 } //01 00 
		$a_01_3 = {63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 66 00 72 00 69 00 65 00 6e 00 64 00 6c 00 2e 00 64 00 6c 00 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}