
rule Ransom_Linux_Ransomhub_D{
	meta:
		description = "Ransom:Linux/Ransomhub.D,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4e 6f 74 65 46 69 6c 65 4e 61 6d 65 15 6a 73 6f 6e 3a 22 6e 6f 74 65 5f 66 69 6c 65 5f 6e 61 6d 65 22 03 0c 4e 6f 74 65 46 75 6c 6c 54 65 78 74 } //1 潎整楆敬慎敭樕潳㩮渢瑯彥楦敬湟浡≥ః潎整畆汬敔瑸
		$a_03_1 = {53 65 6c 66 44 65 6c 65 74 65 12 6a 73 ?? 6e 3a 22 73 65 6c 66 5f 64 65 6c 65 74 65 22 } //1
		$a_01_2 = {2a 6d 61 69 6e 2e 42 75 69 6c 64 43 6f 6e 66 69 67 } //1 *main.BuildConfig
		$a_01_3 = {57 68 69 74 65 46 6f 6c 64 65 72 73 14 6a 73 6f 6e 3a 22 77 68 69 74 65 5f 66 6f 6c 64 65 72 73 22 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}