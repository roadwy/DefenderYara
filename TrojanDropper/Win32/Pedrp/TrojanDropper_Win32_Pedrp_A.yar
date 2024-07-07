
rule TrojanDropper_Win32_Pedrp_A{
	meta:
		description = "TrojanDropper:Win32/Pedrp.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 8a 14 3e 32 d0 88 14 3e 46 3b f3 72 e0 } //1
		$a_03_1 = {83 c9 ff 33 c0 c6 44 24 90 01 01 76 c6 44 24 90 01 01 6f c6 44 24 90 01 01 2e c6 44 24 90 01 01 68 88 54 24 10 90 00 } //1
		$a_03_2 = {f3 a5 8b cb 68 80 00 00 00 83 e1 03 f3 a4 8b 3d 90 01 04 6a 03 50 6a 01 8d 44 24 90 01 01 68 00 00 00 80 50 ff d7 90 00 } //1
		$a_00_3 = {5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 \CurrentVersion\Run
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}