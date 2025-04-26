
rule Trojan_AndroidOS_Fakecalls_HT{
	meta:
		description = "Trojan:AndroidOS/Fakecalls.HT,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {75 70 64 61 74 65 52 65 63 6f 72 64 4c 6f 63 61 74 69 6f 6e 53 56 } //1 updateRecordLocationSV
		$a_01_1 = {74 68 6f 72 6f 75 67 68 66 61 72 65 53 56 } //1 thoroughfareSV
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}