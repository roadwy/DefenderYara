
rule Ransom_Linux_Soleenya_A3{
	meta:
		description = "Ransom:Linux/Soleenya.A3,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_80_0 = {48 6f 77 20 54 6f 20 52 65 73 74 6f 72 65 20 59 6f 75 72 20 46 69 6c 65 73 2e 74 78 74 } //How To Restore Your Files.txt  02 00 
		$a_80_1 = {53 4f 4c 45 45 4e 59 41 20 52 41 4e 53 4f 4d 57 41 52 45 } //SOLEENYA RANSOMWARE  02 00 
		$a_80_2 = {59 4f 55 52 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 } //YOUR FILES HAVE BEEN ENCRYPTED  02 00 
		$a_80_3 = {2e 73 6c 6e 79 61 } //.slnya  00 00 
	condition:
		any of ($a_*)
 
}