
rule Trojan_MacOS_Macrena_A_MTB{
	meta:
		description = "Trojan:MacOS/Macrena.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 61 63 68 6f 4d 61 6e 20 2d 20 72 6f 79 20 67 20 62 69 76 } //01 00  MachoMan - roy g biv
		$a_01_1 = {54 ff 75 e0 56 53 50 33 c0 b0 c4 cd 80 83 f8 00 7e 30 83 c4 14 8d 3c 06 53 56 80 7e 06 08 74 3c 0f b6 46 04 03 f0 3b f7 72 f0 5e 5b 73 d2 } //01 00 
		$a_01_2 = {6a 08 56 53 50 6a 03 58 cd 80 83 c4 10 56 ad 91 ad 5e 0f c1 04 24 e2 41 91 0f b1 4c 24 04 75 12 6a 2c 56 53 50 b0 03 cd 80 83 c4 10 83 7e 24 00 75 13 } //01 00 
		$a_01_3 = {3d ce fa ed fe 75 5d ad 83 f8 07 75 57 ad ad 83 f8 02 75 50 ad 85 c0 74 4b 97 6a 00 50 6a 08 56 53 50 6a 03 58 cd 80 83 c4 10 56 ad 91 ad 5e 0f c1 04 24 e2 41 91 0f b1 4c 24 04 75 12 6a 2c 56 53 50 b0 03 cd 80 83 c4 10 83 7e 24 00 75 13 } //00 00 
		$a_00_4 = {5d 04 00 } //00 74 
	condition:
		any of ($a_*)
 
}