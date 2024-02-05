
rule Ransom_Win32_DMREncryptor_PA_MTB{
	meta:
		description = "Ransom:Win32/DMREncryptor.PA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 21 21 21 20 52 45 41 44 20 54 48 49 53 20 21 21 21 2e 68 74 61 } //01 00 
		$a_01_1 = {54 68 65 44 4d 52 5f 45 6e 63 72 79 70 74 65 72 } //01 00 
		$a_01_2 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 } //01 00 
		$a_01_3 = {62 61 63 6b 67 72 6f 75 6e 64 2e 70 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}