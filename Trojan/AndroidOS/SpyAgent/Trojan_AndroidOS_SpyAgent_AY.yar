
rule Trojan_AndroidOS_SpyAgent_AY{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.AY,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 50 41 43 45 5f 57 5f 43 4f 4e 56 } //02 00 
		$a_01_1 = {77 68 74 5f 63 68 61 74 } //02 00 
		$a_01_2 = {53 50 41 43 45 5f 4e 4f 54 49 46 59 54 } //02 00 
		$a_01_3 = {67 65 74 43 72 65 63 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}