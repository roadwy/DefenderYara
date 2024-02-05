
rule TrojanSpy_Win32_Bhoban{
	meta:
		description = "TrojanSpy:Win32/Bhoban,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 06 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {85 c0 74 11 8b 55 08 c6 02 e9 8b 45 0c 2b c2 83 e8 05 89 42 01 c9 c2 08 00 } //05 00 
		$a_03_1 = {b8 44 00 00 00 e8 19 00 00 00 33 c9 89 4d e4 a1 90 01 02 00 10 83 c0 11 ff e0 51 b9 56 01 00 00 8b cf 59 c3 90 00 } //01 00 
		$a_01_2 = {8d 49 02 66 39 19 75 f0 3d e0 1e 00 00 75 5f c7 44 3c 1c 01 00 00 80 c7 05 } //00 00 
	condition:
		any of ($a_*)
 
}