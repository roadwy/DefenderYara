
rule Ransom_Win32_Purubutu_B{
	meta:
		description = "Ransom:Win32/Purubutu.B,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b7 54 5a fe 33 d7 66 89 54 58 fe 43 4e 75 e5 } //01 00 
		$a_01_1 = {44 00 65 00 6c 00 65 00 74 00 65 00 20 00 53 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 41 00 6c 00 6c 00 20 00 2f 00 51 00 75 00 69 00 65 00 74 00 } //01 00  Delete Shadows /All /Quiet
		$a_01_2 = {6e 00 61 00 74 00 69 00 76 00 65 00 2e 00 43 00 42 00 43 00 } //0a 00  native.CBC
		$a_01_3 = {36 01 24 01 29 01 20 01 36 01 05 01 37 01 2c 01 35 01 2a 01 29 01 24 01 6b 01 2b 01 20 01 31 01 } //00 00  ĶĤĩĠĶąķĬĵĪĩĤūīĠı
		$a_00_4 = {5d 04 00 00 98 21 03 80 5c 21 } //00 00 
	condition:
		any of ($a_*)
 
}