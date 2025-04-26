
rule Trojan_BAT_Aenjaris_S_MTB{
	meta:
		description = "Trojan:BAT/Aenjaris.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 73 65 72 76 65 72 6a 61 72 76 69 73 2e 73 79 74 65 73 2e 6e 65 74 2f 72 65 73 6f 75 72 63 65 5f 76 69 72 2f 63 6f 6d 6d 61 6e 64 2e 70 68 70 } //1 http://serverjarvis.sytes.net/resource_vir/command.php
		$a_81_1 = {6a 64 66 68 64 73 6b 6a 64 67 66 79 75 73 35 34 33 35 33 30 36 36 35 } //1 jdfhdskjdgfyus543530665
		$a_81_2 = {4d 65 6e 75 20 49 6e 69 63 69 61 72 5c 50 72 6f 67 72 61 6d 61 73 5c 49 6e 69 63 69 61 6c 69 7a 61 72 } //1 Menu Iniciar\Programas\Inicializar
		$a_81_3 = {46 6f 74 6f 73 } //1 Fotos
		$a_81_4 = {41 72 71 75 69 76 6f 73 } //1 Arquivos
		$a_81_5 = {52 65 67 69 73 74 72 6f 73 } //1 Registros
		$a_81_6 = {57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 } //1 Windows Update
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}