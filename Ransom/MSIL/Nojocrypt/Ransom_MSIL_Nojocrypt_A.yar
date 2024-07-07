
rule Ransom_MSIL_Nojocrypt_A{
	meta:
		description = "Ransom:MSIL/Nojocrypt.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 75 6d 61 69 6e 73 20 73 61 6e 73 20 65 6d 70 6c 6f 69 73 2c 20 65 6e 20 63 68 65 72 63 68 65 20 70 61 73 20 6c 65 73 } //1 humains sans emplois, en cherche pas les
		$a_01_1 = {4d 6f 79 65 6e 20 64 65 20 50 61 79 65 6d 65 6e 74 3a } //1 Moyen de Payement:
		$a_01_2 = {56 65 75 69 6c 6c 65 7a 20 65 6e 76 6f 79 65 72 20 6c 65 73 20 63 6f 64 65 73 20 64 65 73 20 63 61 72 74 65 73 } //1 Veuillez envoyer les codes des cartes
		$a_01_3 = {46 69 6c 65 4c 6f 63 6b 65 72 2e } //1 FileLocker.
		$a_01_4 = {66 72 2d 66 72 2f 61 63 68 65 74 65 72 2f 74 72 6f 75 76 65 72 2d 64 65 73 2d 70 6f 69 6e 74 73 2d 64 65 2d 76 65 6e 74 65 2f } //1 fr-fr/acheter/trouver-des-points-de-vente/
		$a_01_5 = {62 6c 6f 63 61 67 65 20 73 61 6e 73 20 50 61 79 65 72 20 73 65 72 61 20 61 75 74 6f 6d 61 74 69 71 75 65 6d 65 6e 74 20 72 65 6a 65 74 } //1 blocage sans Payer sera automatiquement rejet
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}