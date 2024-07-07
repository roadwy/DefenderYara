
rule TrojanDownloader_BAT_Gabrenehu_A{
	meta:
		description = "TrojanDownloader:BAT/Gabrenehu.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {2f 00 69 00 6e 00 68 00 61 00 6c 00 74 00 73 00 61 00 6e 00 67 00 61 00 62 00 65 00 6e 00 2e 00 65 00 75 00 2f 00 77 00 70 00 2d 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2f 00 } //4 /inhaltsangaben.eu/wp-content/
		$a_01_1 = {77 00 70 00 2d 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2f 00 70 00 6c 00 75 00 67 00 69 00 6e 00 73 00 2f 00 78 00 6d 00 6c 00 2f 00 32 00 30 00 31 00 32 00 31 00 30 00 30 00 2e 00 7a 00 69 00 70 00 } //4 wp-content/plugins/xml/2012100.zip
		$a_01_2 = {66 00 75 00 63 00 6b 00 65 00 72 00 30 00 32 00 30 00 32 00 23 00 } //2 fucker0202#
		$a_01_3 = {66 00 6c 00 61 00 73 00 68 00 2e 00 7a 00 69 00 70 00 } //2 flash.zip
		$a_01_4 = {73 65 6e 68 61 64 6f 7a 69 70 } //1 senhadozip
		$a_01_5 = {6e 6f 6d 65 64 6f 7a 69 70 } //1 nomedozip
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=9
 
}