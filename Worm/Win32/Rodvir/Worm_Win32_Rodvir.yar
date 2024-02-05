
rule Worm_Win32_Rodvir{
	meta:
		description = "Worm:Win32/Rodvir,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff ff 85 c0 7e 1a 8a 93 70 50 40 00 30 16 46 43 81 e3 07 00 00 80 79 05 4b 83 cb f8 43 48 75 e6 } //01 00 
		$a_03_1 = {81 74 24 04 36 63 02 16 6a 00 53 e8 90 01 02 ff ff 3b 44 24 04 72 3c 6a 02 6a 00 8b 44 24 0c f7 d8 50 53 e8 90 00 } //01 00 
		$a_03_2 = {81 75 f8 36 63 02 16 6a 00 53 e8 90 01 02 ff ff 3b 45 f8 0f 82 b1 00 00 00 6a 02 6a 00 8b 45 f8 f7 d8 50 53 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}