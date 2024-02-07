
rule TrojanSpy_Win32_SSonce_B{
	meta:
		description = "TrojanSpy:Win32/SSonce.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 45 c8 66 c7 45 cc 01 00 66 c7 45 ce 20 00 c7 45 c0 28 00 00 00 6a 00 } //01 00 
		$a_01_1 = {83 e8 02 74 0b 48 74 16 48 74 21 48 74 2c eb 38 } //01 00 
		$a_01_2 = {43 46 47 00 ff ff ff ff 01 00 00 00 23 00 } //01 00 
		$a_03_3 = {0f 84 86 00 00 00 50 a1 90 01 02 44 00 50 e8 90 01 02 fe ff 85 c0 90 00 } //01 00 
		$a_03_4 = {0f 84 89 00 00 00 68 05 01 00 00 8d 85 f7 fe ff ff 50 e8 90 01 02 fe ff 50 e8 90 01 02 fe ff 8d 85 f0 fe ff ff 8d 95 f7 fe ff ff b9 05 01 00 00 90 00 } //01 00 
		$a_00_5 = {54 43 6e 52 61 77 4b 65 79 42 6f 61 72 64 } //01 00  TCnRawKeyBoard
		$a_00_6 = {75 52 65 67 69 73 74 72 79 } //00 00  uRegistry
	condition:
		any of ($a_*)
 
}