
rule Trojan_AndroidOS_BrowBot_C{
	meta:
		description = "Trojan:AndroidOS/BrowBot.C,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 73 6f 75 72 63 65 7a 5f 90 01 02 00 90 00 } //01 00 
		$a_03_1 = {2f 64 61 74 61 5f 90 01 02 2f 69 6e 64 65 78 5f 90 01 02 2e 70 68 70 00 90 00 } //01 00 
		$a_03_2 = {2f 53 6d 73 52 65 63 65 69 76 65 72 41 63 74 69 76 69 74 79 5f 90 01 02 3b 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}