
rule Ransom_MSIL_BrickCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/BrickCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 } //01 00  vssadmin delete shadows /all /quiet
		$a_01_1 = {2e 00 62 00 72 00 69 00 63 00 6b 00 } //01 00  .brick
		$a_01_2 = {5c 00 49 00 44 00 5f 00 47 00 45 00 4e 00 45 00 52 00 41 00 54 00 45 00 2e 00 54 00 58 00 54 00 } //01 00  \ID_GENERATE.TXT
		$a_01_3 = {44 00 4f 00 4e 00 27 00 54 00 20 00 54 00 4f 00 55 00 43 00 48 00 20 00 54 00 48 00 49 00 53 00 20 00 46 00 49 00 4c 00 45 00 21 00 } //00 00  DON'T TOUCH THIS FILE!
	condition:
		any of ($a_*)
 
}