
rule Ransom_Win32_SlamCryptor_PAA_MTB{
	meta:
		description = "Ransom:Win32/SlamCryptor.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 49 4d 20 4c 6f 67 6f 6e 55 49 2e 65 78 65 } //01 00 
		$a_81_1 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //01 00 
		$a_01_2 = {73 6c 61 6d 72 61 6e 73 6f 6d 77 61 72 65 } //01 00 
		$a_81_3 = {73 6c 61 6d 2f 6b 65 79 2e 74 78 74 } //00 00 
	condition:
		any of ($a_*)
 
}