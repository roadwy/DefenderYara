
rule Ransom_Linux_Akira_B_MTB{
	meta:
		description = "Ransom:Linux/Akira.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 6b 69 72 61 6c 6b 7a 78 7a 71 32 64 73 72 7a 73 72 76 62 72 32 78 67 62 62 75 32 77 67 73 6d 78 72 79 64 34 63 73 67 66 61 6d 65 67 35 32 6e 37 65 66 76 72 32 69 64 2e 6f 6e 69 6f 6e 2e } //5 akiralkzxzq2dsrzsrvbr2xgbbu2wgsmxryd4csgfameg52n7efvr2id.onion.
		$a_01_1 = {2d 2d 65 6e 63 72 79 70 74 69 6f 6e 5f 70 61 74 68 } //1 --encryption_path
		$a_01_2 = {2d 2d 65 6e 63 72 79 70 74 69 6f 6e 5f 70 65 72 63 65 6e 74 } //1 --encryption_percent
		$a_01_3 = {2e 61 6b 69 72 61 } //1 .akira
		$a_01_4 = {61 6b 69 72 61 5f 72 65 61 64 6d 65 2e 74 78 74 } //1 akira_readme.txt
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}