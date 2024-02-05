
rule TrojanSpy_Win32_Fireox_B{
	meta:
		description = "TrojanSpy:Win32/Fireox.B,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 5c 73 69 67 6e 6f 6e 73 32 2e 74 78 74 00 } //01 00 
		$a_01_1 = {66 66 70 73 63 61 63 68 65 2e 74 6d 70 } //01 00 
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 6f 7a 69 6c 6c 61 5c 4d 6f 7a 69 6c 6c 61 20 46 69 72 65 66 6f 78 } //01 00 
		$a_01_3 = {46 74 70 50 75 74 46 69 6c 65 41 } //01 00 
		$a_01_4 = {33 c0 55 68 74 55 40 00 64 ff 30 64 89 20 6a 00 6a 00 6a 00 6a 01 68 84 55 40 00 e8 b7 f7 ff ff 8b d8 6a 00 68 00 00 00 08 6a 01 8b 45 08 } //00 00 
	condition:
		any of ($a_*)
 
}