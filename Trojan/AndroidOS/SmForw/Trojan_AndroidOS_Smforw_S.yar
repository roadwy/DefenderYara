
rule Trojan_AndroidOS_Smforw_S{
	meta:
		description = "Trojan:AndroidOS/Smforw.S,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 65 63 72 65 74 54 61 6c 6b 41 70 70 } //1 secretTalkApp
		$a_01_1 = {72 65 61 64 79 20 74 6f 20 72 65 63 65 69 76 65 20 73 6d 73 } //1 ready to receive sms
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_AndroidOS_Smforw_S_2{
	meta:
		description = "Trojan:AndroidOS/Smforw.S,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 73 65 72 76 6c 65 74 2f 53 65 6e 64 4d 61 73 73 61 67 65 32 } //2 /servlet/SendMassage2
		$a_01_1 = {44 65 41 64 6d 69 6e 52 65 63 69 76 65 72 } //2 DeAdminReciver
		$a_01_2 = {2f 73 65 72 76 6c 65 74 2f 43 6f 6e 74 61 63 74 73 55 70 6c 6f 61 64 } //2 /servlet/ContactsUpload
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}