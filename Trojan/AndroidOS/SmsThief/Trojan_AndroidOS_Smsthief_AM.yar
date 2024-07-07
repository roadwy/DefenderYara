
rule Trojan_AndroidOS_Smsthief_AM{
	meta:
		description = "Trojan:AndroidOS/Smsthief.AM,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 67 67 69 6f 72 6e 61 2d 77 65 62 2e 6f 72 67 2f 73 6d 73 2e 70 68 70 } //1 aggiorna-web.org/sms.php
		$a_01_1 = {6d 65 73 73 61 67 65 20 63 6f 6e 74 65 6e 74 } //1 message content
		$a_01_2 = {69 6e 63 6f 6d 69 6e 67 20 6d 65 73 73 61 67 65 } //1 incoming message
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}