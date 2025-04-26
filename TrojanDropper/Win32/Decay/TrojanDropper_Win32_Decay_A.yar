
rule TrojanDropper_Win32_Decay_A{
	meta:
		description = "TrojanDropper:Win32/Decay.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b c1 99 f7 fe 41 8a 82 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 83 f9 0a 7e e9 33 c9 8d a4 24 00 00 00 00 } //1
		$a_01_1 = {7e e9 bf 01 00 00 00 bb 02 00 00 00 bd 03 00 00 00 b8 04 00 00 00 33 c9 } //2
		$a_01_2 = {8b 10 89 16 8a 48 04 88 4e 04 83 c6 05 c6 06 e9 46 2b c6 40 89 06 83 ee 06 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=3
 
}