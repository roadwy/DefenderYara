
rule Ransom_Win64_Henasome_BH_MTB{
	meta:
		description = "Ransom:Win64/Henasome.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 6e 74 69 2d 41 6e 61 6c 79 73 69 73 } //1 Anti-Analysis
		$a_01_1 = {53 61 6e 64 62 6f 78 20 44 65 74 65 63 74 69 6f 6e } //1 Sandbox Detection
		$a_01_2 = {59 4f 55 52 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 } //1 YOUR FILES HAVE BEEN ENCRYPTED
		$a_01_3 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 vssadmin delete shadows /all /quiet
		$a_01_4 = {44 69 73 61 62 6c 65 41 6e 74 69 56 69 72 75 73 } //1 DisableAntiVirus
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}