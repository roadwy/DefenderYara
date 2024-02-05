
rule Worm_Win32_Fubalca_A{
	meta:
		description = "Worm:Win32/Fubalca.A,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 07 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8a 55 f8 80 c2 41 e8 90 01 02 ff ff 8b 95 90 01 02 ff ff 8d 45 f0 b9 90 01 04 e8 90 01 02 ff ff 8d 45 f4 50 68 3f 00 0f 00 6a 00 68 90 01 04 68 01 00 00 80 e8 90 01 02 ff ff 33 c0 89 45 ec 6a 04 8d 45 ec 50 6a 04 6a 00 68 90 01 04 8b 45 f4 50 90 00 } //0a 00 
		$a_02_1 = {8d 45 ec ba 05 00 00 00 e8 90 01 02 ff ff 6a 00 68 90 01 04 e8 90 01 02 ff ff 68 90 01 02 00 00 e8 90 01 02 ff ff 6a 00 8d 85 90 01 02 ff ff 8b 4d ec ba 90 01 04 e8 90 01 02 ff ff 8b 85 90 01 02 ff ff e8 90 01 02 ff ff 50 e8 90 01 02 ff ff 6a 00 90 00 } //01 00 
		$a_00_2 = {41 75 74 6f 52 75 6e 2e 69 6e 66 } //01 00 
		$a_00_3 = {5b 41 75 74 6f 52 75 6e 5d } //01 00 
		$a_00_4 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d } //01 00 
		$a_00_5 = {73 68 65 6c 6c 5c 41 75 74 6f 5c 63 6f 6d 6d 61 6e 64 3d } //01 00 
		$a_00_6 = {4e 6f 44 72 69 76 65 54 79 70 65 41 75 74 6f 52 75 6e } //00 00 
	condition:
		any of ($a_*)
 
}