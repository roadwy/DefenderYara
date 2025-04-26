
rule Ransom_Linux_Defray_A_MTB{
	meta:
		description = "Ransom:Linux/Defray.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_00_0 = {4e 45 57 53 5f 46 4f 52 5f 45 49 47 53 49 21 2e 74 78 74 } //1 NEWS_FOR_EIGSI!.txt
		$a_00_1 = {66 72 61 6e 63 65 2e 65 69 67 73 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //1 france.eigs@protonmail.com
		$a_00_2 = {59 6f 75 20 63 61 6e 20 6d 61 69 6c 20 75 73 20 6f 6e 65 20 63 72 79 70 74 65 64 20 64 6f 63 75 6d 65 6e 74 } //1 You can mail us one crypted document
		$a_00_3 = {43 48 41 4e 47 49 4e 47 20 63 6f 6e 74 65 6e 74 20 6f 72 20 6e 61 6d 65 73 20 6f 66 20 63 72 79 70 74 65 64 20 66 69 6c 65 73 20 28 2a 2e 33 31 67 73 31 29 } //1 CHANGING content or names of crypted files (*.31gs1)
		$a_00_4 = {67 5f 52 61 6e 73 6f 6d 48 65 61 64 65 72 } //1 g_RansomHeader
		$a_00_5 = {72 61 6e 73 6f 6d 77 61 72 65 2e 63 } //1 ransomware.c
		$a_00_6 = {52 65 61 64 4d 65 53 74 6f 72 65 46 6f 72 44 69 72 } //1 ReadMeStoreForDir
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}