
rule Trojan_AndroidOS_SpyAgent_JH{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.JH,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {64 6f 4d 6f 62 69 6c 65 42 65 61 74 } //02 00  doMobileBeat
		$a_01_1 = {67 65 74 50 68 6f 6e 65 4e 75 6d 43 68 61 6e 67 65 4e 75 6d } //02 00  getPhoneNumChangeNum
		$a_01_2 = {67 65 74 50 68 6f 6e 65 4e 75 6d 43 6f 6d 65 } //00 00  getPhoneNumCome
	condition:
		any of ($a_*)
 
}