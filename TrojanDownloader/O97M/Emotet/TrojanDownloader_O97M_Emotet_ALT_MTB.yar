
rule TrojanDownloader_O97M_Emotet_ALT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.ALT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 65 73 63 75 65 6c 61 64 65 63 69 6e 65 6d 7a 61 2e 63 6f 6d 2e 61 72 2f 5f 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 2f 49 42 6c 6a 2f } //1 www.escueladecinemza.com.ar/_installation/IBlj/
		$a_01_1 = {63 69 65 6e 63 69 61 73 2d 65 78 61 63 74 61 73 2e 63 6f 6d 2e 61 72 2f 6f 6c 64 2f 42 75 70 75 62 7a 31 74 72 68 2f } //1 ciencias-exactas.com.ar/old/Bupubz1trh/
		$a_01_2 = {63 6f 75 6e 74 65 72 61 63 74 2e 63 6f 6d 2e 62 72 2f 77 70 2d 61 64 6d 69 6e 2f 57 57 63 41 43 4a 46 33 59 6e 2f } //1 counteract.com.br/wp-admin/WWcACJF3Yn/
		$a_01_3 = {63 72 65 65 6d 6f 2e 70 6c 2f 77 70 2d 61 64 6d 69 6e 2f 30 75 44 55 48 4a 34 4b 56 41 77 2f } //1 creemo.pl/wp-admin/0uDUHJ4KVAw/
		$a_01_4 = {64 61 6e 63 65 66 6f 78 32 34 2e 64 65 2f 74 65 6d 70 6c 61 74 65 73 2f 6f 77 54 2f } //1 dancefox24.de/templates/owT/
		$a_01_5 = {66 6f 63 75 73 6d 65 64 69 63 61 2e 69 6e 2f 66 6d 6c 69 62 2f 54 59 69 51 64 63 45 6a 39 46 57 30 2f } //1 focusmedica.in/fmlib/TYiQdcEj9FW0/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=1
 
}