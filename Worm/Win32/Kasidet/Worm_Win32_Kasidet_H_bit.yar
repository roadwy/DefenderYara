
rule Worm_Win32_Kasidet_H_bit{
	meta:
		description = "Worm:Win32/Kasidet.H!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {64 a1 30 00 00 00 8b 40 0c 53 8b 58 0c 56 57 8b 7d 08 8b f3 81 f7 90 01 04 8b 56 30 e8 90 01 03 ff 8b c8 e8 90 01 03 ff 3b c7 74 17 8b 36 3b de 74 0a 85 f6 74 06 83 7e 30 00 75 dd 90 00 } //01 00 
		$a_03_1 = {6a 04 68 00 30 00 00 8d 47 01 50 6a 00 ff 15 90 01 03 00 8b f0 85 f6 74 1f 57 53 56 e8 90 01 03 ff 83 c4 0c 33 c0 85 ff 74 0a 66 83 34 46 02 40 3b c7 72 f6 90 00 } //01 00 
		$a_03_2 = {42 80 3c 0a 00 75 f9 3b f2 73 0f 0f be 14 0e 33 c2 69 c0 90 01 04 46 eb dc 5e c3 56 be 90 01 04 33 d2 e8 90 01 03 ff 85 c0 74 16 0f b7 04 51 33 f0 69 f6 90 01 04 42 e8 90 01 03 ff 3b d0 72 ea 8b c6 5e c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}