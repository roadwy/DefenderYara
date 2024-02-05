
rule Ransom_Win32_CryaklCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/CryaklCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 52 45 41 44 4d 45 2e 74 78 74 } //01 00 
		$a_01_1 = {61 73 73 68 6f 6c 65 } //01 00 
		$a_01_2 = {43 4c 20 31 2e 33 2e 31 2e 30 } //01 00 
		$a_01_3 = {63 68 63 70 20 31 32 35 31 20 3e 20 6e 75 6c } //01 00 
		$a_01_4 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e } //01 00 
		$a_01_5 = {62 69 6e 3a 63 6f 6d 3a 65 78 65 3a 62 61 74 3a 70 6e 67 3a 62 6d 70 3a 64 61 74 3a 6c 6f 67 3a 69 6e 69 3a 64 6c 6c 3a 73 79 73 3a } //00 00 
	condition:
		any of ($a_*)
 
}