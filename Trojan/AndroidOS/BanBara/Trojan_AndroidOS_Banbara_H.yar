
rule Trojan_AndroidOS_Banbara_H{
	meta:
		description = "Trojan:AndroidOS/Banbara.H,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6d 61 6e 64 6f 44 65 6c 65 74 61 72 41 6c 6c } //2 ComandoDeletarAll
		$a_01_1 = {74 72 61 76 65 72 73 65 4e 6f 64 65 49 6e 69 63 69 6f } //2 traverseNodeInicio
		$a_01_2 = {61 70 69 2f 76 31 2f 50 65 67 61 73 75 73 2f 44 65 6c 65 74 61 72 43 6f 6d 61 6e 64 6f 54 6f 64 6f 73 } //2 api/v1/Pegasus/DeletarComandoTodos
		$a_01_3 = {52 65 63 75 72 73 69 76 69 64 61 64 65 54 65 78 74 } //2 RecursividadeText
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=6
 
}