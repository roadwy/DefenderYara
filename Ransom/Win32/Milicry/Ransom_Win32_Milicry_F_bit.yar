
rule Ransom_Win32_Milicry_F_bit{
	meta:
		description = "Ransom:Win32/Milicry.F!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2d 2d 6b 69 6c 6c 73 74 61 72 74 } //01 00 
		$a_01_1 = {2d 2d 6b 69 6c 6c 6d 65 74 72 6f } //01 00 
		$a_01_2 = {2d 2d 73 62 6f 70 65 6e 61 76 } //01 00 
		$a_01_3 = {2d 2d 72 65 73 65 78 70 6c 72 } //01 00 
		$a_01_4 = {63 6d 64 2e 65 78 65 20 2f 63 20 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //01 00 
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 74 61 72 74 50 61 67 65 } //00 00 
	condition:
		any of ($a_*)
 
}