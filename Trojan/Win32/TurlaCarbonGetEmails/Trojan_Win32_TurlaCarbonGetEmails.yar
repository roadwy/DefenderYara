
rule Trojan_Win32_TurlaCarbonGetEmails{
	meta:
		description = "Trojan:Win32/TurlaCarbonGetEmails,SIGNATURE_TYPE_PEHSTR,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {52 00 65 00 6d 00 6f 00 76 00 69 00 6e 00 67 00 20 00 72 00 65 00 63 00 69 00 70 00 69 00 65 00 6e 00 74 00 3a 00 } //1 Removing recipient:
		$a_01_1 = {5d 00 20 00 52 00 65 00 63 00 65 00 69 00 76 00 65 00 64 00 20 00 6d 00 61 00 69 00 6c 00 20 00 69 00 74 00 65 00 6d 00 20 00 66 00 72 00 6f 00 6d 00 } //1 ] Received mail item from
		$a_01_2 = {5d 00 20 00 42 00 6c 00 6f 00 63 00 6b 00 69 00 6e 00 67 00 20 00 6d 00 61 00 69 00 6c 00 20 00 69 00 74 00 65 00 6d 00 20 00 66 00 72 00 6f 00 6d 00 } //1 ] Blocking mail item from
		$a_01_3 = {67 65 74 5f 41 74 74 61 63 68 6d 65 6e 74 73 } //1 get_Attachments
		$a_01_4 = {45 6e 76 65 6c 6f 70 65 52 65 63 69 70 69 65 6e 74 } //1 EnvelopeRecipient
		$a_01_5 = {42 6c 6f 63 6b 4d 73 67 } //1 BlockMsg
		$a_01_6 = {67 65 74 5f 4d 65 73 73 61 67 65 } //1 get_Message
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}