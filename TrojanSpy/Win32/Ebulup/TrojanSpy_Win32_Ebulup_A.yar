
rule TrojanSpy_Win32_Ebulup_A{
	meta:
		description = "TrojanSpy:Win32/Ebulup.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff d6 8d bd fc fe ff ff 4f 8a 47 01 47 84 c0 75 f8 8d } //01 00 
		$a_01_1 = {0f 86 07 01 00 00 32 c0 8d bd fc fe ff ff 8b cb f3 aa 53 8d 85 fc fe ff ff 50 6a 00 } //01 00 
		$a_01_2 = {83 c4 10 3b c6 75 2c 85 f6 74 1e 8b 7b 3c 68 ff ff 00 00 89 74 1f 58 e8 } //01 00 
		$a_01_3 = {8b 4d 08 2b ca 8d 74 02 02 c6 03 09 f3 a4 80 3b 5c 75 17 8d 7c 02 01 80 3f 22 75 0e c6 03 22 8b 4d 08 2b ca 8d 74 02 02 f3 a4 } //00 00 
		$a_00_4 = {87 10 } //00 00 
	condition:
		any of ($a_*)
 
}