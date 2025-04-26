
rule Ransom_Win64_Albabat_AC_MTB{
	meta:
		description = "Ransom:Win64/Albabat.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 49 49 42 43 67 4b 43 41 51 45 41 77 2f 34 4d 70 6e 77 37 79 56 39 4e 44 7a 6a 49 53 67 4e 65 73 57 53 48 6a 37 41 } //1 MIIBCgKCAQEAw/4Mpnw7yV9NDzjISgNesWSHj7A
		$a_01_1 = {54 68 65 20 22 20 52 61 6e 73 6f 6d 77 61 72 65 22 20 69 73 20 61 20 63 72 6f 73 73 2d 70 6c 61 74 66 6f 72 6d 20 72 61 6e 73 6f 6d 77 61 72 65 20 74 68 61 74 20 65 6e 63 72 79 70 74 73 } //1 The " Ransomware" is a cross-platform ransomware that encrypts
		$a_01_2 = {66 69 6c 65 73 20 6f 6e 20 79 6f 75 72 20 6d 61 63 68 69 6e 65 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 files on your machine have been encrypted
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}