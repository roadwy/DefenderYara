
rule Ransom_Win32_Tobfy_O{
	meta:
		description = "Ransom:Win32/Tobfy.O,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {51 68 f5 72 99 3d 6a 01 e8 90 01 02 00 00 90 00 } //01 00 
		$a_03_1 = {5c 57 4f 52 4b 5c 57 4f 52 4b 5f 50 45 43 45 50 42 5c 90 02 20 5c 69 6e 6a 63 5c 52 65 6c 65 61 73 65 5c 69 6e 6a 63 2e 70 64 62 90 00 } //01 00 
		$a_01_2 = {03 55 f8 0f be 02 83 f0 01 8b 4d fc 03 4d f8 88 01 eb af } //00 00 
	condition:
		any of ($a_*)
 
}