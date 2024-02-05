
rule Ransom_Win32_Stitur_A{
	meta:
		description = "Ransom:Win32/Stitur.A,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8d 05 d8 01 00 00 01 d8 83 38 00 75 05 83 c0 04 01 08 ff 30 58 61 ff 64 24 dc } //05 00 
		$a_03_1 = {66 81 71 16 00 20 90 09 14 00 66 81 38 4d 5a 75 90 01 01 8b 48 3c 03 c8 81 39 50 45 00 00 75 90 00 } //01 00 
		$a_00_2 = {73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //00 00 
		$a_00_3 = {7e 15 00 00 d3 22 05 fd 07 c0 } //b9 c2 
	condition:
		any of ($a_*)
 
}