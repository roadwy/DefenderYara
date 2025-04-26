
rule Trojan_BAT_AgentTesla_AMKOA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMKOA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 07 00 09 00 00 "
		
	strings :
		$a_80_0 = {23 65 6d 61 6e 73 65 72 23 } //#emanser#  1
		$a_80_1 = {63 6f 47 6a 52 4e 49 61 41 4c 75 57 } //coGjRNIaALuW  1
		$a_80_2 = {23 73 73 61 70 23 } //#ssap#  1
		$a_80_3 = {62 78 6e 79 72 61 6e 77 68 4f 74 68 } //bxnyranwhOth  1
		$a_80_4 = {6c 6c 64 2e 74 6e 65 6d 65 67 61 6e 61 4d 2e 6d 65 74 73 79 53 } //lld.tnemeganaM.metsyS  1
		$a_80_5 = {6c 6c 64 2e 6d 65 74 73 79 53 } //lld.metsyS  1
		$a_80_6 = {6c 6c 64 2e 67 6e 69 77 61 72 44 2e 6d 65 74 73 79 53 } //lld.gniwarD.metsyS  1
		$a_80_7 = {6c 6c 64 2e 65 72 6f 43 2e 6d 65 74 73 79 53 } //lld.eroC.metsyS  1
		$a_80_8 = {65 78 65 6e 69 77 3a 74 65 67 72 61 74 2f 20 2b 67 75 62 65 64 2f 20 36 38 58 3a 6d 72 6f 66 74 61 6c 70 2f 20 2b 65 7a 69 6d 69 74 70 6f 2f } //exeniw:tegrat/ +gubed/ 68X:mroftalp/ +ezimitpo/  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=7
 
}