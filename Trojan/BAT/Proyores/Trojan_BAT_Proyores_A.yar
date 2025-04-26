
rule Trojan_BAT_Proyores_A{
	meta:
		description = "Trojan:BAT/Proyores.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {45 3a 5c 50 72 6f 79 65 63 74 6f 73 5c 4e 65 67 6f 63 69 61 64 6f 72 65 73 5c 53 71 6c 4e 65 74 5c 6f 62 6a 5c 44 65 62 75 67 5c 53 71 6c 4e 65 74 2e 70 64 62 } //5 E:\Proyectos\Negociadores\SqlNet\obj\Debug\SqlNet.pdb
		$a_01_1 = {45 3a 5c 70 72 6f 6a 65 63 74 73 5c 4e 65 67 6f 63 69 61 64 6f 72 65 73 5c 53 71 6c 4e 65 74 5c 6f 62 6a 5c 44 65 62 75 67 5c 53 71 6c 4e 65 74 2e 70 64 62 } //5 E:\projects\Negociadores\SqlNet\obj\Debug\SqlNet.pdb
		$a_01_2 = {43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 72 65 6e 7a 6f 6e 5c 45 73 63 72 69 74 6f 72 69 6f 5c 50 72 6f 79 65 63 74 6f 73 5c 4e 65 67 6f 63 69 61 64 6f 72 65 73 5c 53 56 4e 20 45 6e 74 65 6e 64 69 65 6e 64 6f 5c 45 75 72 6f 2d 43 41 46 54 41 5c 52 6f 53 69 73 74 65 6d 61 5c 53 71 6c 4e 65 74 5c 6f 62 6a 5c 44 65 62 75 67 5c 53 71 6c 4e 65 74 2e 70 64 62 } //5 C:\Documents and Settings\renzon\Escritorio\Proyectos\Negociadores\SVN Entendiendo\Euro-CAFTA\RoSistema\SqlNet\obj\Debug\SqlNet.pdb
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=5
 
}