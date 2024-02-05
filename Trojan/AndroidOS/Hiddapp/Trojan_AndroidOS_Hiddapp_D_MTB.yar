
rule Trojan_AndroidOS_Hiddapp_D_MTB{
	meta:
		description = "Trojan:AndroidOS/Hiddapp.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {61 6e 64 72 6f 69 64 2f 73 75 70 70 6f 72 74 2f 76 37 2f 61 70 70 2f 72 65 63 65 69 76 65 72 73 } //02 00 
		$a_01_1 = {73 65 74 56 6d 50 6f 6c 69 63 79 } //01 00 
		$a_01_2 = {48 61 72 64 77 61 72 65 49 64 73 } //01 00 
		$a_01_3 = {44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}