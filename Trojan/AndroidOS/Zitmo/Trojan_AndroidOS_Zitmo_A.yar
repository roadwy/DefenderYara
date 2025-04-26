
rule Trojan_AndroidOS_Zitmo_A{
	meta:
		description = "Trojan:AndroidOS/Zitmo.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 73 6f 66 74 74 68 72 69 66 74 79 2e 63 6f 6d 2f 73 65 63 75 72 69 74 79 2e 6a 73 70 } //1 http://softthrifty.com/security.jsp
		$a_01_1 = {61 63 74 69 76 61 74 69 6f 6e 5f 70 72 6f 6d 74 } //1 activation_promt
		$a_01_2 = {73 79 73 74 65 6d 73 65 63 75 72 69 74 79 36 2f 67 6d 73 2f 53 6d 73 52 65 63 65 69 76 65 72 } //1 systemsecurity6/gms/SmsReceiver
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}