
rule Ransom_Win64_Akira_ZA_MTB{
	meta:
		description = "Ransom:Win64/Akira.ZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 61 6b 69 72 61 } //10 .akira
		$a_01_1 = {61 6b 69 72 61 5f 72 65 61 64 6d 65 2e 74 78 74 } //10 akira_readme.txt
		$a_01_2 = {2e 61 72 69 6b 61 } //1 .arika
		$a_01_3 = {68 74 74 70 73 3a 2f 2f 61 6b 69 72 61 } //1 https://akira
		$a_01_4 = {79 6f 75 72 20 63 6f 72 70 6f 72 61 74 65 20 64 61 74 61 20 70 72 69 6f 72 20 74 6f 20 65 6e 63 72 79 70 74 69 6f 6e } //1 your corporate data prior to encryption
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=22
 
}