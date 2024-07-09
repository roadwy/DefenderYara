
rule TrojanDropper_Win32_Phdet_A{
	meta:
		description = "TrojanDropper:Win32/Phdet.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 e9 68 05 ad 89 0d 6a 00 6a 01 c7 44 24 } //1
		$a_03_1 = {7e 15 6a 7a 6a 61 e8 ?? ?? ?? ?? 83 c4 08 66 89 04 77 46 3b f3 7c eb } //1
		$a_01_2 = {5f 00 44 00 45 00 4c 00 00 00 00 00 45 00 72 00 72 00 6f 00 72 00 43 00 6f 00 6e 00 74 00 72 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}