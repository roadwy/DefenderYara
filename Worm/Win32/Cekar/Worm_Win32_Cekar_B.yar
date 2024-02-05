
rule Worm_Win32_Cekar_B{
	meta:
		description = "Worm:Win32/Cekar.B,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 00 69 69 69 2e 83 c0 04 c7 00 65 78 65 00 6a 00 6a 00 6a 02 6a 00 6a 00 68 00 00 00 40 52 ff 55 14 89 45 44 3d ff ff ff ff 74 78 } //01 00 
		$a_01_1 = {01 ee b8 47 65 74 50 39 06 75 f1 b8 72 6f 63 41 39 46 04 75 e7 8b 5a 24 01 eb 66 8b 0c 4b 8b 5a 1c 01 eb 8b 04 8b 01 e8 55 83 ec 50 89 e5 89 45 10 68 6c 6f 63 00 68 61 6c 41 6c 68 47 6c 6f 62 54 57 ff 55 10 } //00 00 
	condition:
		any of ($a_*)
 
}