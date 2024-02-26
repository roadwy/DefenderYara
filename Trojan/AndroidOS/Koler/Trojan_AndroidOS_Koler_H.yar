
rule Trojan_AndroidOS_Koler_H{
	meta:
		description = "Trojan:AndroidOS/Koler.H,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {36 35 38 39 79 34 35 39 67 6a 34 30 35 38 72 74 67 75 } //02 00  6589y459gj4058rtgu
		$a_01_1 = {43 48 45 43 4b 5f 46 4f 52 5f 55 4e 4c 4f 43 4b } //00 00  CHECK_FOR_UNLOCK
	condition:
		any of ($a_*)
 
}