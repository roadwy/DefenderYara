
rule Ransom_MSIL_SharpCrypter_PA_MTB{
	meta:
		description = "Ransom:MSIL/SharpCrypter.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 00 30 00 78 00 30 00 4d 00 34 00 52 00 } //01 00  .0x0M4R
		$a_01_1 = {52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //01 00  Ransomware.Properties.Resources
		$a_01_2 = {30 78 30 4d 34 52 20 61 20 6d 61 6c 68 65 75 72 65 75 73 65 6d 65 6e 74 20 69 6e 66 65 63 74 } //01 00  0x0M4R a malheureusement infect
		$a_03_3 = {5c 4f 50 53 49 45 5c 50 72 6f 6a 65 74 5f 52 61 6e 73 6f 6d 77 61 72 65 5f 63 73 68 61 72 70 5f 42 52 4f 43 41 52 44 5f 42 41 53 53 41 49 44 5f 42 45 4e 48 41 44 44 41 44 5c 52 61 6e 73 6f 6d 77 61 72 65 5c 52 61 6e 73 6f 6d 77 61 72 65 5c 90 02 30 5c 41 64 6f 62 65 20 52 65 61 64 65 72 2e 70 64 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}