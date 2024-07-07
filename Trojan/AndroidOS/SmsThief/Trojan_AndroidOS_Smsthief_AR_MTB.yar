
rule Trojan_AndroidOS_Smsthief_AR_MTB{
	meta:
		description = "Trojan:AndroidOS/Smsthief.AR!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 4d 53 4f 42 53 65 72 76 65 72 } //1 SMSOBServer
		$a_01_1 = {73 65 6e 64 70 68 6f 6e 65 } //1 sendphone
		$a_01_2 = {73 65 6e 64 77 77 77 } //1 sendwww
		$a_01_3 = {42 61 64 53 4d 53 52 65 63 65 69 76 65 72 } //1 BadSMSReceiver
		$a_01_4 = {63 6f 6d 2f 64 65 63 72 79 70 74 73 74 72 69 6e 67 6d 61 6e 61 67 65 72 } //1 com/decryptstringmanager
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}