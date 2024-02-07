
rule Trojan_AndroidOS_Mantis_A{
	meta:
		description = "Trojan:AndroidOS/Mantis.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {6f 6a 41 63 74 69 76 69 74 79 } //02 00  ojActivity
		$a_01_1 = {76 76 6f 52 65 63 65 69 76 65 72 } //02 00  vvoReceiver
		$a_01_2 = {73 31 69 53 65 72 76 69 63 65 } //00 00  s1iService
	condition:
		any of ($a_*)
 
}