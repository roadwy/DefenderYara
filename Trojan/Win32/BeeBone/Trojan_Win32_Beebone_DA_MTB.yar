
rule Trojan_Win32_Beebone_DA_MTB{
	meta:
		description = "Trojan:Win32/Beebone.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {41 4b 41 44 45 4d 49 45 4c 45 56 45 52 } //1 AKADEMIELEVER
		$a_81_1 = {4f 70 74 69 6d 20 43 6c 61 73 73 } //1 Optim Class
		$a_81_2 = {49 52 49 53 48 57 4f 4d 45 4e } //1 IRISHWOMEN
		$a_81_3 = {54 65 6b 6e 6f 6c 6f 67 69 76 75 72 64 65 72 69 6e 67 73 70 72 6f 6a 65 6b 74 65 72 73 } //1 Teknologivurderingsprojekters
		$a_81_4 = {53 4f 4c 44 45 42 52 4f 44 45 52 53 } //1 SOLDEBRODERS
		$a_81_5 = {53 70 6f 72 74 73 66 69 73 6b 65 72 66 6f 72 62 75 6e 64 65 6e 65 73 38 } //1 Sportsfiskerforbundenes8
		$a_81_6 = {44 61 67 70 65 6e 67 65 6c 6f 76 65 6e 65 73 } //1 Dagpengelovenes
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}