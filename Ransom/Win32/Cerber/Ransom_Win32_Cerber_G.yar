
rule Ransom_Win32_Cerber_G{
	meta:
		description = "Ransom:Win32/Cerber.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {c1 e8 10 33 c2 69 c0 6b ca eb 85 8b c8 c1 e9 0d 33 c8 } //01 00 
		$a_03_1 = {75 02 0f 31 8b 15 90 01 04 6b f6 64 8b c8 c1 e1 0b 33 c8 90 00 } //01 00 
		$a_01_2 = {33 c0 6a 0f ff 35 38 43 43 00 66 89 43 04 66 a1 e0 42 43 00 c7 03 44 72 62 52 66 89 43 15 ff 15 } //ff ff 
		$a_00_3 = {4c 6f 63 61 6c 20 70 72 69 76 61 74 65 2e 6b 65 79 20 66 69 6c 65 20 66 6f 75 6e 64 } //00 00 
		$a_00_4 = {80 10 } //00 00 
	condition:
		any of ($a_*)
 
}