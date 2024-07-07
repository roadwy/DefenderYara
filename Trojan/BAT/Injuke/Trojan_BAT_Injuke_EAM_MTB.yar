
rule Trojan_BAT_Injuke_EAM_MTB{
	meta:
		description = "Trojan:BAT/Injuke.EAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {1a 2d 24 26 28 90 01 01 00 00 0a 06 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 1c 2d 13 26 07 16 07 8e 69 15 2d 0d 26 26 26 07 0c de 10 0a 2b da 0b 2b eb 28 90 01 01 00 00 0a 2b ef 26 de be 90 00 } //3
		$a_01_1 = {63 00 6f 00 6d 00 69 00 63 00 6d 00 61 00 73 00 74 00 65 00 72 00 2e 00 6f 00 72 00 67 00 2e 00 75 00 6b 00 2f 00 69 00 6d 00 67 00 2f 00 63 00 73 00 73 00 2f 00 64 00 65 00 73 00 69 00 67 00 6e 00 2f 00 66 00 61 00 62 00 72 00 69 00 63 00 2f 00 62 00 6f 00 2f 00 53 00 65 00 71 00 71 00 67 00 64 00 73 00 72 00 68 00 2e 00 62 00 6d 00 70 00 } //2 comicmaster.org.uk/img/css/design/fabric/bo/Seqqgdsrh.bmp
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}