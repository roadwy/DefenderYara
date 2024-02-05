
rule Ransom_Win32_Nubelonguerypt_A{
	meta:
		description = "Ransom:Win32/Nubelonguerypt.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 79 6c 2e 69 6e 69 } //01 00 
		$a_00_1 = {2e 79 6c 00 2a 2e 2a } //01 00 
		$a_02_2 = {69 63 6f 2e 69 63 6f 90 02 04 31 2e 6a 70 67 90 00 } //01 00 
		$a_00_3 = {2a 2e 65 7c 2a 2e 64 6f 63 7c 2a 2e 6a 70 67 7c 2a 2e 70 6e 67 7c 2a 2e 74 78 74 7c 2a 2e 70 64 66 7c 2a 2e 77 70 73 } //00 00 
		$a_00_4 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}