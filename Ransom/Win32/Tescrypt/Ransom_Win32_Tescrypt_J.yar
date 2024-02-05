
rule Ransom_Win32_Tescrypt_J{
	meta:
		description = "Ransom:Win32/Tescrypt.J,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d c7 04 00 00 75 15 68 34 08 00 00 ff 15 90 01 04 8d 45 c0 50 ff d6 85 c0 74 de 90 00 } //01 00 
		$a_01_1 = {76 73 73 61 00 } //01 00 
		$a_01_2 = {00 64 6d 69 6e 00 } //01 00 
		$a_01_3 = {73 68 61 64 6f 77 73 } //01 00 
		$a_01_4 = {2f 61 6c 6c } //01 00 
		$a_01_5 = {2f 51 75 69 65 74 } //00 00 
	condition:
		any of ($a_*)
 
}