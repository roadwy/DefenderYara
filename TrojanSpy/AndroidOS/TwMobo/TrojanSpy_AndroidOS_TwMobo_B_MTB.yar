
rule TrojanSpy_AndroidOS_TwMobo_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/TwMobo.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 67 73 65 72 76 69 63 65 2f 61 63 74 69 76 69 74 79 2f 41 64 6d } //1 Lcom/gservice/activity/Adm
		$a_00_1 = {63 6f 6e 74 72 6f 6c 65 5f 72 65 6d 6f 74 6f } //1 controle_remoto
		$a_00_2 = {41 63 65 73 73 69 62 69 6c 69 64 61 64 65 5f 43 6c 69 63 6b } //1 Acessibilidade_Click
		$a_00_3 = {2f 61 75 74 6f 62 6f 74 2f 41 63 65 73 73 69 62 69 6c 69 64 61 64 65 } //1 /autobot/Acessibilidade
		$a_00_4 = {73 6f 6c 75 74 69 6f 6e 73 64 65 76 6e 65 77 61 79 2e 6e 65 74 } //1 solutionsdevneway.net
		$a_03_5 = {2f 67 61 74 65 77 61 79 2f [0-10] 2e 70 68 70 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_03_5  & 1)*1) >=5
 
}