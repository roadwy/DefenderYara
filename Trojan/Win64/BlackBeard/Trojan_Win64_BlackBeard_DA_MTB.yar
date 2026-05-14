
rule Trojan_Win64_BlackBeard_DA_MTB{
	meta:
		description = "Trojan:Win64/BlackBeard.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_81_0 = {6a 66 64 67 68 6b 6a 66 64 67 6b 6c 68 6a 64 66 68 67 73 66 64 30 39 67 39 30 34 35 6a 6c 6b 64 66 6a 6c 6b 67 65 64 66 67 35 39 34 39 30 34 35 64 66 6a 67 64 66 6c 67 6c 6a 6b 64 66 67 64 66 } //10 jfdghkjfdgklhjdfhgsfd09g9045jlkdfjlkgedfg5949045dfjgdflgljkdfgdf
		$a_03_1 = {5c 00 70 00 68 00 6f 00 6e 00 69 00 78 00 [0-06] 5c 00 70 00 68 00 6f 00 65 00 6e 00 69 00 78 00 [0-06] 5c 00 78 00 36 00 34 00 5c 00 [0-0f] 5c 00 70 00 68 00 6f 00 65 00 6e 00 69 00 78 00 2e 00 70 00 64 00 62 00 } //1
		$a_03_2 = {5c 70 68 6f 6e 69 78 [0-06] 5c 70 68 6f 65 6e 69 78 [0-06] 5c 78 36 34 5c [0-0f] 5c 70 68 6f 65 6e 69 78 2e 70 64 62 } //1
		$a_81_3 = {65 6e 63 72 79 70 74 65 64 } //1 encrypted
	condition:
		((#a_81_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_81_3  & 1)*1) >=12
 
}