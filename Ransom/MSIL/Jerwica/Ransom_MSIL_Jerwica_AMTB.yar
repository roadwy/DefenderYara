
rule Ransom_MSIL_Jerwica_AMTB{
	meta:
		description = "Ransom:MSIL/Jerwica!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_80_0 = {4a 65 72 77 69 63 61 52 61 6e 73 6f 6d 2e 70 64 62 } //JerwicaRansom.pdb  2
		$a_80_1 = {67 65 74 5f 76 69 63 74 69 6d 5f 69 64 } //get_victim_id  1
		$a_80_2 = {4a 65 72 77 69 63 61 52 61 6e 73 6f 6d 5f 50 72 6f 63 65 73 73 65 64 42 79 46 6f 64 79 20 } //JerwicaRansom_ProcessedByFody   1
		$a_80_3 = {6a 65 72 77 69 63 61 5f 69 6e 66 65 63 74 65 64 2e 74 78 74 20 } //jerwica_infected.txt   1
		$a_80_4 = {2e 6a 65 72 77 69 63 61 } //.jerwica  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=3
 
}