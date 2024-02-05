
rule Worm_Win32_Rortoti_A{
	meta:
		description = "Worm:Win32/Rortoti.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff 5c cc 40 00 c7 85 44 ff ff ff 08 80 00 00 c7 85 3c ff ff ff 68 cc 40 00 c7 85 34 ff ff ff 08 80 } //01 00 
		$a_01_1 = {2b 33 71 b5 68 36 b1 b6 33 96 fe 49 95 84 74 01 68 85 f8 48 2a 3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 b5 } //01 00 
		$a_01_2 = {5c 69 67 66 78 68 6f 73 74 2e 65 78 65 } //01 00 
		$a_01_3 = {7b 41 41 38 39 30 30 39 35 46 46 2d 35 38 37 36 2d 46 46 46 46 2d 37 36 54 48 2d 37 37 38 39 37 35 34 34 46 46 31 43 45 7d } //00 00 
		$a_00_4 = {80 10 } //00 00 
	condition:
		any of ($a_*)
 
}