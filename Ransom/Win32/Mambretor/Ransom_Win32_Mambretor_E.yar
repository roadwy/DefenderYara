
rule Ransom_Win32_Mambretor_E{
	meta:
		description = "Ransom:Win32/Mambretor.E,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 70 75 62 6c 69 63 2e 55 6e 6b 6f 6e 77 5c 44 65 73 6b 74 6f 70 5c 43 52 50 5f 39 35 5f 30 38 5f 33 30 5f 76 33 5c 43 52 50 5c 52 65 6c 65 61 73 65 5c 4d 6f 75 6e 74 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}