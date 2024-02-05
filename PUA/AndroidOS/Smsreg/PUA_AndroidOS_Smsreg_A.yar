
rule PUA_AndroidOS_Smsreg_A{
	meta:
		description = "PUA:AndroidOS/Smsreg.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 68 2f 6e 74 68 2f 61 6e 64 72 6f 69 64 2f 75 74 69 6c 73 2f 54 65 6c 65 70 68 6f 6e 79 55 74 69 6c 73 } //01 00 
		$a_01_1 = {76 65 72 69 66 79 53 75 62 73 63 72 69 70 74 69 6f 6e } //01 00 
		$a_01_2 = {46 49 52 53 54 5f 53 4d 53 5f 53 45 4e 54 } //01 00 
		$a_01_3 = {73 63 6d 73 64 6b 2f 61 73 79 6e 63 2f 53 63 6d 56 65 72 69 66 79 53 75 62 73 63 72 69 70 74 69 6f 6e 52 65 71 75 65 73 74 } //00 00 
	condition:
		any of ($a_*)
 
}