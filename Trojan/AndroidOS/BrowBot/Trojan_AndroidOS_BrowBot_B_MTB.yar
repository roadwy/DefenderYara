
rule Trojan_AndroidOS_BrowBot_B_MTB{
	meta:
		description = "Trojan:AndroidOS/BrowBot.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 38 70 2e 6e 65 74 2f 74 71 66 58 44 6e } //01 00  a8p.net/tqfXDn
		$a_01_1 = {63 72 65 64 65 6e 74 69 61 6c 73 4c 61 75 6e 63 68 65 72 5f } //01 00  credentialsLauncher_
		$a_03_2 = {64 61 74 61 5f 90 01 02 2f 69 6e 73 74 61 6c 6c 5f 90 01 02 2e 70 68 70 90 00 } //01 00 
		$a_03_3 = {53 6d 73 52 65 63 65 69 76 65 72 5f 90 01 02 00 90 00 } //01 00 
		$a_03_4 = {63 68 65 63 6b 65 72 5f 90 01 02 2e 70 68 70 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}