
rule Ransom_MSIL_WannaMadCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/WannaMadCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 57 00 61 00 6e 00 6e 00 61 00 4d 00 61 00 64 00 } //01 00  RansomwareWannaMad
		$a_01_1 = {2e 00 68 00 61 00 63 00 6b 00 65 00 64 00 } //01 00  .hacked
		$a_01_2 = {2e 00 57 00 61 00 6e 00 6e 00 61 00 4d 00 61 00 64 00 } //02 00  .WannaMad
		$a_01_3 = {4f 00 6f 00 70 00 73 00 2e 00 2e 00 20 00 59 00 6f 00 75 00 20 00 48 00 61 00 73 00 20 00 42 00 65 00 65 00 6e 00 20 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 2e 00 } //02 00  Oops.. You Has Been Encrypted.
		$a_03_4 = {5c 57 61 6e 6e 61 4d 61 64 5c 90 02 10 5c 90 02 10 44 65 62 75 67 5c 57 61 6e 6e 61 4d 61 64 2e 70 64 62 90 00 } //00 00 
		$a_00_5 = {5d 04 00 00 84 } //98 04 
	condition:
		any of ($a_*)
 
}