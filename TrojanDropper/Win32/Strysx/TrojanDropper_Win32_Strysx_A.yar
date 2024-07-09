
rule TrojanDropper_Win32_Strysx_A{
	meta:
		description = "TrojanDropper:Win32/Strysx.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {75 2d 8d 44 24 10 50 e8 ?? ff ff ff 59 ff 70 04 ff 15 ?? ?? 15 13 8d 4c 24 10 8b f0 e8 ?? 01 00 00 68 ?? ?? 15 13 56 ff 15 ?? ?? 15 13 ff d0 5e } //3
		$a_01_1 = {62 6f 74 00 6d 6f 64 5f 65 6d 61 69 6c 73 00 00 63 72 79 70 74 65 72 00 } //1
		$a_01_2 = {73 79 73 00 77 69 6e 33 32 00 00 00 6d 73 78 6d 00 } //1
	condition:
		((#a_02_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}