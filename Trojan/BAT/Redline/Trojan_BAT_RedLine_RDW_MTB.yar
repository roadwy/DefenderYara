
rule Trojan_BAT_RedLine_RDW_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 00 65 00 6e 00 75 00 6d 00 62 00 65 00 72 00 65 00 64 00 } //1 Renumbered
		$a_01_1 = {4d 69 63 72 6f 73 6f 66 74 20 43 6f 6d 70 61 6e 79 20 4f 70 65 72 61 74 69 6e 67 20 53 79 73 74 65 6d } //1 Microsoft Company Operating System
		$a_01_2 = {4d 69 63 72 6f 73 6f 66 74 20 43 6f 6e 74 72 61 63 74 20 49 6d 70 6f 72 74 65 72 2f 45 78 70 6f 72 74 65 72 } //1 Microsoft Contract Importer/Exporter
		$a_01_3 = {65 64 6f 63 70 4f 70 4f 6f 4e 72 65 68 63 74 61 70 73 69 44 6c 65 64 6f 4d 65 63 69 76 72 65 53 6d 65 74 73 79 53 39 39 33 31 39 } //1 edocpOpOoNrehctapsiDledoMecivreSmetsyS99319
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}