
rule Trojan_AndroidOS_SmsThief_T{
	meta:
		description = "Trojan:AndroidOS/SmsThief.T,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 70 6e 77 61 72 6e 69 6e 67 32 } //01 00  vpnwarning2
		$a_01_1 = {73 68 6f 72 74 61 6c 6c 5f 42 52 } //00 00  shortall_BR
	condition:
		any of ($a_*)
 
}
rule Trojan_AndroidOS_SmsThief_T_2{
	meta:
		description = "Trojan:AndroidOS/SmsThief.T,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {6c 6f 67 2f 42 61 64 53 4d 53 52 65 63 65 69 76 65 72 3b } //02 00  log/BadSMSReceiver;
		$a_01_1 = {41 74 46 77 64 53 65 72 76 69 63 65 24 73 65 6e 64 43 6f 6e 74 61 63 74 73 54 65 78 74 } //02 00  AtFwdService$sendContactsText
		$a_01_2 = {53 65 6e 64 43 6f 6e 74 65 6e 74 42 79 4d 61 69 6c } //00 00  SendContentByMail
	condition:
		any of ($a_*)
 
}