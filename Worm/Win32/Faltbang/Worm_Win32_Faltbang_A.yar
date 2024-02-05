
rule Worm_Win32_Faltbang_A{
	meta:
		description = "Worm:Win32/Faltbang.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {74 0b 68 40 7e 05 00 ff 15 90 01 04 e8 90 01 04 50 66 c7 45 cc 02 00 ff 15 90 01 04 68 99 05 00 00 89 45 d0 90 00 } //01 00 
		$a_03_1 = {74 04 3c 2a 75 03 c6 01 5f 8d 85 90 01 02 ff ff 47 50 e8 90 01 04 3b f8 59 72 b9 90 00 } //01 00 
		$a_01_2 = {63 6d 64 20 2f 63 20 6c 73 6e 73 73 2e 65 78 65 20 2d 53 20 25 73 20 2d 55 20 73 61 20 2d 50 20 25 73 } //00 00 
	condition:
		any of ($a_*)
 
}