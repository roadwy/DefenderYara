
rule Ransom_Win32_Grymegat_B{
	meta:
		description = "Ransom:Win32/Grymegat.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 69 6d 67 2e 70 68 70 3f 67 69 6d 6d 65 49 6d 67 00 } //01 00 
		$a_01_1 = {26 53 74 61 74 75 73 3d 4c 6f 63 6b 20 48 54 54 50 2f 31 2e 31 00 } //01 00 
		$a_01_2 = {72 65 67 20 61 64 64 20 22 48 4b 43 55 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 22 20 2f 76 20 } //00 00 
	condition:
		any of ($a_*)
 
}