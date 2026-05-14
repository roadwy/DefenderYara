
rule Ransom_Win64_Devman_D{
	meta:
		description = "Ransom:Win64/Devman.D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 45 56 4d 41 4e 20 46 69 6c 65 20 45 6e 63 72 79 70 74 69 6f 6e 20 55 74 69 6c 69 74 79 } //1 DEVMAN File Encryption Utility
		$a_01_1 = {45 6e 63 72 79 70 74 69 6f 6e 20 63 6f 6d 70 6c 65 74 65 2e 20 46 69 6c 65 73 20 65 6e 63 72 79 70 74 65 64 3a 20 } //1 Encryption complete. Files encrypted: 
		$a_01_2 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 65 6e 63 72 79 70 74 65 64 20 64 72 69 76 65 3a 20 } //1 Successfully encrypted drive: 
		$a_01_3 = {46 61 69 6c 65 64 20 74 6f 20 73 65 74 20 77 61 6c 6c 70 61 70 65 72 3a } //1 Failed to set wallpaper:
		$a_01_4 = {44 72 6f 70 70 65 64 20 72 61 6e 73 6f 6d 20 6e 6f 74 65 20 61 74 3a 20 } //1 Dropped ransom note at: 
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}