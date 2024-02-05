
rule Ransom_Win32_Nokonoko_PC_MTB{
	meta:
		description = "Ransom:Win32/Nokonoko.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 32 68 74 62 32 74 76 63 32 68 74 62 32 74 76 } //01 00 
		$a_01_1 = {62 6d 39 72 62 32 35 76 61 32 38 3d } //01 00 
		$a_01_2 = {52 45 56 4d 52 56 52 46 58 31 4e 49 51 55 52 50 56 77 3d 3d } //01 00 
		$a_01_3 = {52 55 35 44 55 6c 6c 51 56 46 39 4f 52 56 52 58 54 31 4a 4c } //0a 00 
		$a_03_4 = {8b d0 c1 ce 02 89 45 f8 c1 c2 05 03 55 80 8b c3 33 c6 81 c7 90 01 04 23 45 fc 33 c3 81 c3 90 01 04 03 c2 03 c7 90 00 } //00 00 
		$a_00_5 = {5d 04 00 00 d1 8a 05 80 5c 2c } //00 00 
	condition:
		any of ($a_*)
 
}