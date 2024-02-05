
rule TrojanDropper_Win32_Emold_G{
	meta:
		description = "TrojanDropper:Win32/Emold.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {58 8b 40 18 50 eb 0d 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 89 c3 e8 90 01 04 89 c6 e8 90 01 04 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 00 53 ff d6 54 90 00 } //01 00 
		$a_03_1 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 00 00 90 01 04 31 d2 31 c0 90 00 } //01 00 
		$a_00_2 = {30 07 2c 04 4f e2 f9 } //00 00 
	condition:
		any of ($a_*)
 
}