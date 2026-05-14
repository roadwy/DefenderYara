
rule Ransom_MSIL_FakeWUCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/FakeWUCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 2e 00 70 00 68 00 70 00 } //3 ransomware.php
		$a_01_1 = {42 00 55 00 49 00 4c 00 44 00 20 00 52 00 41 00 4e 00 53 00 4f 00 4d 00 45 00 57 00 41 00 52 00 45 00 20 00 46 00 4f 00 52 00 20 00 4d 00 45 00 } //1 BUILD RANSOMEWARE FOR ME
		$a_01_2 = {41 00 6d 00 62 00 61 00 72 00 61 00 77 00 61 00 20 00 43 00 79 00 62 00 65 00 72 00 20 00 41 00 72 00 6d 00 79 00 } //1 Ambarawa Cyber Army
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}