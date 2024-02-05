
rule Ransom_Win32_CerberCrypt_PAA_MTB{
	meta:
		description = "Ransom:Win32/CerberCrypt.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 6f 72 32 77 65 62 2e 6f 72 67 } //01 00 
		$a_01_1 = {72 65 6d 6f 76 65 5f 73 68 61 64 6f 77 73 } //01 00 
		$a_01_2 = {43 45 52 42 45 52 20 52 41 4e 53 4f 4d 57 41 52 45 } //01 00 
		$a_01_3 = {22 2e 76 62 6f 78 22 2c 22 2e 76 64 69 22 } //01 00 
		$a_01_4 = {69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //00 00 
	condition:
		any of ($a_*)
 
}