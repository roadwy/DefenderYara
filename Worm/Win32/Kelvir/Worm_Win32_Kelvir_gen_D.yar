
rule Worm_Win32_Kelvir_gen_D{
	meta:
		description = "Worm:Win32/Kelvir.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {7b 00 45 00 4e 00 54 00 45 00 52 00 7d 00 } //02 00 
		$a_01_1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4d 65 73 73 65 6e 67 65 72 5c 6d 73 6d 73 67 73 2e 65 78 65 5c 33 } //03 00 
		$a_01_2 = {53 61 76 65 41 70 70 54 6f 57 69 6e 5f 69 6e 69 } //01 00 
		$a_01_3 = {4d 65 73 73 65 6e 67 65 72 41 50 49 } //00 00 
	condition:
		any of ($a_*)
 
}