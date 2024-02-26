
rule Trojan_AndroidOS_BrowBot_H{
	meta:
		description = "Trojan:AndroidOS/BrowBot.H,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 61 70 69 6e 65 74 63 6f 6d 2e 63 6f 6d 2f 64 61 74 61 5f 31 36 2f 69 6e 64 65 78 5f 31 36 2e 70 68 70 } //02 00  https://www.apinetcom.com/data_16/index_16.php
		$a_01_1 = {68 6f 6d 65 70 61 67 65 55 72 6c 5f 31 36 } //00 00  homepageUrl_16
	condition:
		any of ($a_*)
 
}