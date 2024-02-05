
rule PWS_Win32_Finsgra_A{
	meta:
		description = "PWS:Win32/Finsgra.A,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0a 00 08 00 00 05 00 "
		
	strings :
		$a_03_0 = {c7 45 fc 41 3a 5c 00 ff 90 90 01 04 a3 90 01 04 c6 45 fc 41 8d 45 fc 50 a1 90 01 04 ff 39 90 01 02 00 00 85 c0 74 18 90 00 } //05 00 
		$a_01_1 = {8a c8 80 e9 21 80 f9 5d 77 58 3c 20 74 54 3c 22 } //05 00 
		$a_03_2 = {7e 79 8d 3c 02 8d 41 ff 6a 44 33 d2 59 f7 f1 8b f0 46 33 c0 8b d7 8a 0a 3a cb 88 8c 05 90 01 04 74 08 42 42 40 83 f8 44 7e eb 90 00 } //01 00 
		$a_01_3 = {2f 2f 4d 25 75 2f 73 6e 69 66 66 47 72 61 62 46 69 6c 65 4e 61 6d 65 } //01 00 
		$a_01_4 = {2f 2f 4d 25 75 2f 64 69 73 6b 47 72 61 62 46 69 6c 65 4e 61 6d 65 } //01 00 
		$a_01_5 = {2f 2f 4d 25 75 2f 6c 61 73 74 53 6e 69 66 66 52 65 70 6f 72 74 } //01 00 
		$a_01_6 = {4d 41 49 4c 3d 5c 57 2a 28 5b 41 2d 5a 61 2d 7a 30 2d 39 2d 5f 5c 2e 5d 2b 40 5b 41 2d 5a 61 2d 7a 30 2d 39 2d 5f 5c 2e 5d 2b 5c 2e 5b 41 2d 5a 61 2d 7a 5d 2b 29 } //01 00 
		$a_01_7 = {3d 5c 57 2a 28 5b 41 2d 5a 61 2d 7a 30 2d 39 2d 5f 5c 2e 5d 2b 40 5b 41 2d 5a 61 2d 7a 30 2d 39 2d 5f 5c 2e 5d 2b 5c 2e 5b 41 2d 5a 61 2d 7a 5d 2b 29 5c 29 } //00 00 
	condition:
		any of ($a_*)
 
}