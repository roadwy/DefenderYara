
rule Trojan_BAT_LokiBot_NB_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {28 5b 00 00 06 25 26 11 01 16 11 01 8e 69 28 5c 00 00 06 25 26 13 00 38 cd ff ff ff } //3
		$a_01_1 = {48 6f 73 74 2d 53 65 72 76 65 72 2d 4b 6f 6e 66 69 67 75 72 61 74 69 6f 6e } //1 Host-Server-Konfiguration
		$a_01_2 = {44 45 5f 50 41 47 45 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 DE_PAGE.g.resources
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}