
rule Trojan_Win32_Vundo_AG{
	meta:
		description = "Trojan:Win32/Vundo.AG,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {84 b2 96 b1 b4 ba 1a 10 b6 9c 00 aa 00 34 1d 07 73 00 63 00 6c 00 6a 00 6e 00 76 00 63 00 00 } //01 00 
		$a_00_1 = {6b 00 65 00 79 00 77 00 6f 00 72 00 64 00 73 00 00 00 00 00 61 16 0c d3 af cd d0 11 8a 3e 00 c0 4f c9 e2 6e } //02 00 
		$a_03_2 = {59 6a 00 6a 04 8b f8 57 56 ff 15 90 01 02 01 10 33 c0 85 ff 7e 08 fe 04 30 40 3b c7 7c f8 90 00 } //01 00 
		$a_00_3 = {43 72 65 61 74 69 6e 67 20 70 6f 70 75 70 20 25 73 } //01 00 
		$a_00_4 = {2f 67 6f 2f 3f 63 6d 70 3d } //00 00 
	condition:
		any of ($a_*)
 
}