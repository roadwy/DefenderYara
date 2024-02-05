
rule Ransom_Win32_Gojdue_A{
	meta:
		description = "Ransom:Win32/Gojdue.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 44 65 73 6b 74 6f 70 5c 48 4f 57 5f 54 4f 5f 44 45 43 52 59 50 54 5f 46 49 4c 45 53 2e 68 74 6d 6c } //01 00 
		$a_01_1 = {2e 6f 6e 69 6f 6e 2e 74 6f 2f 64 65 63 72 79 70 74 2f } //01 00 
		$a_01_2 = {3c 70 3e 54 6f 20 64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 } //01 00 
		$a_01_3 = {47 6f 20 62 75 69 6c 64 20 49 44 } //00 00 
	condition:
		any of ($a_*)
 
}