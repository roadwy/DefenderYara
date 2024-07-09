
rule TrojanDropper_Win32_Mariofev_B{
	meta:
		description = "TrojanDropper:Win32/Mariofev.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {76 1e 8d 7c 24 10 4f 8a 14 0f 8b 74 24 14 02 d0 30 14 30 83 f9 04 75 02 33 c9 40 41 3b c5 72 e7 } //3
		$a_03_1 = {75 26 80 be ?? ?? ?? ?? c0 75 1d 80 be ?? ?? ?? ?? 40 75 14 88 96 90 09 02 00 b2 90 90 } //2
		$a_00_2 = {25 00 73 00 5c 00 74 00 72 00 61 00 73 00 68 00 25 00 58 00 00 00 } //1
		$a_01_3 = {5c 63 74 66 6d 6f 6e 2e 65 78 65 00 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}