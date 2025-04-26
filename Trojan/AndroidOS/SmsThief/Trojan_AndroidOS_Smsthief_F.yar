
rule Trojan_AndroidOS_Smsthief_F{
	meta:
		description = "Trojan:AndroidOS/Smsthief.F,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 69 6e 64 4e 6f 64 65 73 42 79 54 65 78 74 76 32 } //1 findNodesByTextv2
		$a_01_1 = {5f 77 69 66 69 70 6f 6c 63 5f 6d 65 74 68 5f } //1 _wifipolc_meth_
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_AndroidOS_Smsthief_F_2{
	meta:
		description = "Trojan:AndroidOS/Smsthief.F,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 69 62 6c 69 73 73 } //2 hibliss
		$a_01_1 = {61 70 61 63 68 65 63 6b 20 6e 6f 74 69 66 69 63 61 74 69 6f 6e 20 6d 65 73 73 61 67 65 20 73 65 72 76 69 63 65 } //2 apacheck notification message service
		$a_01_2 = {4c 63 6f 6d 2f 73 68 6f 75 6e 61 6b 6d 75 6c 61 79 2f 74 65 6c 65 70 68 6f 6e 79 2f 73 6d 73 2f 49 6e 63 6f 6d 69 6e 67 53 6d 73 52 65 63 65 69 76 65 72 } //2 Lcom/shounakmulay/telephony/sms/IncomingSmsReceiver
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}