
rule Trojan_AndroidOS_SpyBanker_AS{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.AS,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 74 61 72 74 4d 79 41 63 63 65 73 73 69 62 69 6c 69 74 79 53 65 72 76 69 63 65 } //02 00  startMyAccessibilityService
		$a_01_1 = {6f 6e 6c 79 66 61 6e 73 2f 4e 6f 74 69 66 79 4c 69 73 74 65 6e 65 72 } //02 00  onlyfans/NotifyListener
		$a_01_2 = {70 65 73 72 6d 69 73 73 } //00 00  pesrmiss
	condition:
		any of ($a_*)
 
}