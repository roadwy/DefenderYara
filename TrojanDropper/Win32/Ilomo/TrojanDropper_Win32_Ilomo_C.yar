
rule TrojanDropper_Win32_Ilomo_C{
	meta:
		description = "TrojanDropper:Win32/Ilomo.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 fe 4b 45 52 4e 8b 78 04 75 0d 81 ff 45 4c 33 32 75 22 89 5d f4 fe c1 81 fe 6e 74 64 6c 75 11 81 ff 6c 2e 64 6c 75 09 } //01 00 
		$a_01_1 = {75 f6 8b 50 04 56 81 e2 00 00 ff ff 57 32 c9 81 3a 4d 5a 90 00 75 4f 8b 42 3c 3d 00 10 00 00 73 45 } //02 00 
		$a_01_2 = {88 5d e1 c6 45 e2 6c 88 5d e3 88 5d e4 88 5d e5 66 c7 45 f0 18 00 66 c7 45 f2 1a 00 ff d0 8b 45 fc 5b c9 c3 } //00 00 
	condition:
		any of ($a_*)
 
}