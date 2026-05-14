
rule Trojan_Win32_GuLoader_SH_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {63 69 72 6b 75 73 73 20 72 69 67 73 73 74 61 74 69 73 74 69 6b 65 72 65 6e 73 20 77 65 61 74 68 65 72 65 64 } //1 cirkuss rigsstatistikerens weathered
		$a_81_1 = {73 69 62 69 6c 61 74 65 64 20 73 6b 61 72 6e 6b 61 73 73 65 6e } //1 sibilated skarnkassen
		$a_81_2 = {70 79 6c 6f 72 6f 70 6c 61 73 74 79 20 72 61 63 65 68 6f 72 73 65 73 } //1 pyloroplasty racehorses
		$a_81_3 = {61 64 6f 70 74 69 76 6d 6f 72 2e 74 69 70 } //1 adoptivmor.tip
		$a_81_4 = {67 6c 79 63 61 65 6d 69 61 2e 67 61 7a } //1 glycaemia.gaz
		$a_81_5 = {6d 61 64 72 65 70 6f 72 61 63 65 61 6e 2e 73 75 67 } //1 madreporacean.sug
		$a_81_6 = {42 61 72 62 65 72 65 6e 2e 63 68 65 } //1 Barberen.che
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}