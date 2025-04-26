
rule Ransom_Win64_PrinceRansom_YAA_MTB{
	meta:
		description = "Ransom:Win64/PrinceRansom.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 72 69 6e 63 65 2d 52 61 6e 73 6f 6d 77 61 72 65 } //1 Prince-Ransomware
		$a_01_1 = {47 6f 20 62 75 69 6c 64 69 6e 66 3a } //1 Go buildinf:
		$a_01_2 = {66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 files have been encrypted
		$a_01_3 = {70 61 79 69 6e 67 20 75 73 20 61 20 72 61 6e 73 6f 6d } //1 paying us a ransom
		$a_01_4 = {6e 6f 74 20 6d 6f 64 69 66 79 20 6f 72 20 72 65 6e 61 6d 65 20 65 6e 63 72 79 70 74 65 64 } //1 not modify or rename encrypted
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}