
rule Trojan_AndroidOS_Koomer_RT{
	meta:
		description = "Trojan:AndroidOS/Koomer.RT,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {6b 6f 6f 73 65 61 6d 69 6e 65 72 67 6c } //1 kooseaminergl
		$a_01_1 = {45 53 6d 73 45 6e 67 53 74 61 72 74 65 64 } //1 ESmsEngStarted
		$a_01_2 = {4d 53 47 5f 47 45 54 5f 50 48 4f 4e 45 5f 4e 55 4d 42 45 52 } //1 MSG_GET_PHONE_NUMBER
		$a_01_3 = {53 74 61 74 75 73 49 73 62 65 67 69 6e } //1 StatusIsbegin
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}