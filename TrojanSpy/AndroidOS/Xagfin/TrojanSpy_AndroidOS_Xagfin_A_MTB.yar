
rule TrojanSpy_AndroidOS_Xagfin_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Xagfin.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {4c 6d 69 6c 2f 70 6f 70 72 44 33 30 2f } //1 Lmil/poprD30/
		$a_00_1 = {4b 4f 44 5f 61 63 74 69 76 5f 50 4f 50 52 5f 44 } //1 KOD_activ_POPR_D
		$a_00_2 = {41 6c 6c 41 62 6f 75 74 50 68 6f 6e 65 43 6d 64 } //1 AllAboutPhoneCmd
		$a_00_3 = {66 65 74 63 68 43 6f 6e 74 61 63 74 73 } //1 fetchContacts
		$a_00_4 = {43 4d 44 20 31 30 31 20 73 75 63 63 65 73 73 } //1 CMD 101 success
		$a_00_5 = {2a 2a 2a 53 4d 53 20 48 69 73 74 6f 72 79 2a 2a 2a } //1 ***SMS History***
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}