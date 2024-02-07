
rule Ransom_MSIL_SamSam_A{
	meta:
		description = "Ransom:MSIL/SamSam.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 73 73 32 2e 70 64 62 } //01 00  \obj\Release\ss2.pdb
		$a_00_1 = {31 00 48 00 62 00 4a 00 75 00 32 00 6b 00 4c 00 34 00 78 00 44 00 4e 00 4b 00 31 00 4c 00 39 00 59 00 55 00 44 00 6b 00 4a 00 6e 00 71 00 68 00 33 00 79 00 69 00 43 00 31 00 31 00 39 00 59 00 4d 00 32 00 } //00 00  1HbJu2kL4xDNK1L9YUDkJnqh3yiC119YM2
	condition:
		any of ($a_*)
 
}