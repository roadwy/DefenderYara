
rule Ransom_Linux_Trigona_C_MTB{
	meta:
		description = "Ransom:Linux/Trigona.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {49 53 20 4e 4f 54 20 45 4e 43 52 59 50 54 45 44 20 46 49 4c 45 20 44 45 54 45 43 54 45 44 21 } //1 IS NOT ENCRYPTED FILE DETECTED!
		$a_00_1 = {65 72 61 73 65 20 61 6c 6c 20 64 61 74 61 } //1 erase all data
		$a_00_2 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 } //1 Successfully encrypted files
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}