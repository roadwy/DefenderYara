
rule Ransom_Win32_Gpcode_G{
	meta:
		description = "Ransom:Win32/Gpcode.G,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {09 c0 74 0f 09 d2 74 0b d3 c9 41 31 08 83 c0 04 4a 75 f5 c3 } //02 00 
		$a_02_1 = {c7 01 5f 47 5f 50 c7 41 04 5f 43 5f 00 68 90 01 04 6a 00 68 01 00 1f 00 e8 90 01 04 09 c0 0f 85 90 01 01 00 00 00 90 00 } //01 00 
		$a_00_2 = {89 c1 81 e1 00 00 00 80 75 55 86 e0 66 3d 01 05 72 25 } //01 00 
		$a_02_3 = {0f 31 25 ff 00 00 00 c0 e8 06 74 0b 83 05 90 01 03 00 14 fe c8 75 f5 90 00 } //01 00 
		$a_01_4 = {43 72 79 70 74 49 6d 70 6f 72 74 4b 65 79 } //00 00  CryptImportKey
	condition:
		any of ($a_*)
 
}