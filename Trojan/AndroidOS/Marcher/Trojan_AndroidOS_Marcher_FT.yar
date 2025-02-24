
rule Trojan_AndroidOS_Marcher_FT{
	meta:
		description = "Trojan:AndroidOS/Marcher.FT,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 75 73 74 6f 6d 43 61 72 64 4e 75 6d 62 65 72 5f 69 6e 70 75 74 54 79 70 65 } //1 CustomCardNumber_inputType
		$a_01_1 = {50 6c 65 61 73 65 20 73 75 62 6d 69 74 20 79 6f 75 72 20 56 65 72 69 66 65 64 20 62 75 79 20 4d 61 73 74 65 72 43 61 72 64 20 50 61 73 73 77 6f 72 64 } //1 Please submit your Verifed buy MasterCard Password
		$a_01_2 = {73 6d 73 5f 68 6f 6f 6b 5f 6e 6f 5f 61 70 69 } //1 sms_hook_no_api
		$a_01_3 = {51 45 52 46 54 45 56 55 52 51 } //1 QERFTEVURQ
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}