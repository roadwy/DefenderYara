
rule TrojanSpy_Win32_Shiotob_B{
	meta:
		description = "TrojanSpy:Win32/Shiotob.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {83 c0 04 81 e9 ?? ?? ?? ?? 31 08 4a 75 f2 } //1
		$a_03_1 = {88 c3 32 1c 0a c1 e8 08 33 04 9d ?? ?? ?? ?? 41 75 ee } //1
		$a_01_2 = {8b d6 83 c2 04 88 02 c6 03 e9 47 } //1
		$a_03_3 = {ba 35 bf a0 be 8b c3 e8 ?? ?? ?? ?? a3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}