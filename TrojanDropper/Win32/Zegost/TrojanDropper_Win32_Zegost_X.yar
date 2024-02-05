
rule TrojanDropper_Win32_Zegost_X{
	meta:
		description = "TrojanDropper:Win32/Zegost.X,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 44 24 2c 56 c6 44 24 2d 69 c6 44 24 2e 72 c6 44 24 2f 74 c6 44 24 30 75 c6 44 24 31 61 c6 44 24 32 6c c6 44 24 33 50 c6 44 24 34 72 c6 44 24 35 6f c6 44 24 36 74 c6 44 24 37 65 c6 44 24 38 63 c6 44 24 39 74 c6 44 24 3a 00 ff 15 } //01 00 
		$a_01_1 = {8b 4c 24 04 8a 14 08 80 c2 7a 88 14 08 8b 4c 24 04 8a 14 08 80 f2 59 88 14 08 40 3b c6 7c e1 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}