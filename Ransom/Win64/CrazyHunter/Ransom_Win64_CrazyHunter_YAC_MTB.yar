
rule Ransom_Win64_CrazyHunter_YAC_MTB{
	meta:
		description = "Ransom:Win64/CrazyHunter.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //1 Go build ID:
		$a_01_1 = {50 72 69 6e 63 65 2d 52 61 6e 73 6f 6d 77 61 72 65 } //1 Prince-Ransomware
		$a_01_2 = {49 27 6d 20 43 72 61 7a 79 48 75 6e 74 65 72 } //1 I'm CrazyHunter
		$a_01_3 = {65 6e 63 72 79 70 74 65 64 20 61 6c 6c 20 79 6f 75 72 20 73 79 73 74 65 6d 73 } //10 encrypted all your systems
		$a_01_4 = {73 74 6f 6c 65 20 79 6f 75 72 20 66 69 6c 65 } //1 stole your file
		$a_01_5 = {6d 61 64 65 20 70 75 62 6c 69 63 } //1 made public
		$a_01_6 = {64 65 6c 65 74 65 20 61 6c 6c 20 74 68 65 20 64 61 74 61 } //1 delete all the data
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=16
 
}