
rule Trojan_AndroidOS_SmsPay_C{
	meta:
		description = "Trojan:AndroidOS/SmsPay.C,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {2e 72 65 63 65 69 76 65 72 2e 49 6e 53 6d 73 52 65 63 65 69 76 65 72 } //02 00 
		$a_01_1 = {73 74 61 72 74 53 64 6b 53 65 72 76 65 72 50 61 79 } //02 00 
		$a_01_2 = {2e 73 65 72 76 69 63 65 73 2e 53 6d 73 44 61 74 61 53 65 72 76 69 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}