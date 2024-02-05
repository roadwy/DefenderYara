
rule Ransom_Win32_Korasom_A{
	meta:
		description = "Ransom:Win32/Korasom.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {59 4f 55 20 48 41 56 45 20 42 45 45 4e 20 49 4e 46 45 43 54 45 44 20 57 49 54 48 20 52 41 4e 53 4f 4d 57 41 52 45 } //01 00 
		$a_01_1 = {50 61 79 6d 65 6e 74 20 70 72 6f 63 65 64 75 72 65 } //01 00 
		$a_01_2 = {6b 61 72 6f 2e 52 65 61 64 4d 65 2e 68 74 6d 6c } //00 00 
	condition:
		any of ($a_*)
 
}