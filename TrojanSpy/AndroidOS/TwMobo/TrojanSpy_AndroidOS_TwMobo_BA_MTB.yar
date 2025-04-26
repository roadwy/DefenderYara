
rule TrojanSpy_AndroidOS_TwMobo_BA_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/TwMobo.BA!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 67 73 65 72 76 69 63 65 2f 61 75 74 6f 62 6f 74 2f 41 63 65 73 73 69 62 69 6c 69 64 61 64 65 } //1 Lcom/gservice/autobot/Acessibilidade
		$a_00_1 = {61 74 75 61 6c 73 65 72 76 69 63 65 6e 6f 76 6f 2e 68 6f 70 74 6f 2e 6f 72 67 } //1 atualservicenovo.hopto.org
		$a_03_2 = {2f 74 65 6c 61 73 [0-10] 2e 70 68 70 3f 68 77 69 64 3d } //1
		$a_00_3 = {63 6f 6e 74 72 6f 6c 65 5f 72 65 6d 6f 74 6f } //1 controle_remoto
		$a_00_4 = {41 63 65 73 73 69 62 69 6c 69 64 61 64 65 5f 43 6c 69 63 6b } //1 Acessibilidade_Click
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}