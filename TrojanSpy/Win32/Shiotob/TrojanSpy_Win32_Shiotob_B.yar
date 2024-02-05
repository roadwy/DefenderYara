
rule TrojanSpy_Win32_Shiotob_B{
	meta:
		description = "TrojanSpy:Win32/Shiotob.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c0 04 81 e9 90 01 04 31 08 4a 75 f2 90 00 } //01 00 
		$a_03_1 = {88 c3 32 1c 0a c1 e8 08 33 04 9d 90 01 04 41 75 ee 90 00 } //01 00 
		$a_01_2 = {8b d6 83 c2 04 88 02 c6 03 e9 47 } //01 00 
		$a_03_3 = {ba 35 bf a0 be 8b c3 e8 90 01 04 a3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}