
rule Ransom_Linux_Weaxor_A_MTB{
	meta:
		description = "Ransom:Linux/Weaxor.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 62 69 77 65 61 78 2e 70 68 70 } //2 /biweax.php
		$a_01_1 = {2e 72 6f 78 } //1 .rox
		$a_01_2 = {6b 65 79 5f 6f 66 5f 74 61 72 67 65 74 } //1 key_of_target
		$a_01_3 = {72 6f 78 61 65 77 2e 74 78 74 } //1 roxaew.txt
		$a_03_4 = {74 74 70 3a 2f 2f 77 65 61 78 6f 72 [0-55] 2e 6f 6e 69 6f 6e 2f } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*2) >=6
 
}