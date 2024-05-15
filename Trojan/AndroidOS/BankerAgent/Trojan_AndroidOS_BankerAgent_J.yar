
rule Trojan_AndroidOS_BankerAgent_J{
	meta:
		description = "Trojan:AndroidOS/BankerAgent.J,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {2f 73 6d 73 2d 72 65 61 64 65 72 2f 61 64 64 } //02 00  /sms-reader/add
		$a_01_1 = {2f 73 69 74 65 2f 6e 75 6d 62 65 72 3f 73 69 74 65 } //00 00  /site/number?site
	condition:
		any of ($a_*)
 
}