
rule Trojan_AndroidOS_Piom_T{
	meta:
		description = "Trojan:AndroidOS/Piom.T,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {79 29 2d 23 73 75 73 70 65 63 74 28 79 29 2d 23 5f 6e 75 6d 62 28 79 29 2d 23 65 72 73 } //01 00  y)-#suspect(y)-#_numb(y)-#ers
		$a_01_1 = {28 79 29 2d 23 75 72 6c } //00 00  (y)-#url
	condition:
		any of ($a_*)
 
}
rule Trojan_AndroidOS_Piom_T_2{
	meta:
		description = "Trojan:AndroidOS/Piom.T,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 6c 65 61 73 65 20 69 6e 70 75 74 20 31 36 20 64 69 67 69 74 20 63 61 72 64 20 6e 75 6d 62 65 72 } //01 00  Please input 16 digit card number
		$a_01_1 = {4c 63 6f 6d 2f 63 69 74 69 2f 63 69 74 69 62 61 6e 6b 2f 61 63 74 69 76 69 74 79 } //02 00  Lcom/citi/citibank/activity
		$a_01_2 = {65 74 5f 63 75 72 61 64 72 65 73 73 } //01 00  et_curadress
		$a_01_3 = {74 76 5f 63 68 65 63 6b 5f 66 6f 72 5f 6f 66 66 65 72 } //01 00  tv_check_for_offer
		$a_01_4 = {76 61 6c 24 65 64 74 43 76 76 4e 75 6d 62 65 72 } //00 00  val$edtCvvNumber
	condition:
		any of ($a_*)
 
}