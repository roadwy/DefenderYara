
rule Trojan_AndroidOS_Mailthief_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Mailthief.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 61 6d 65 72 61 2f 6e 6f 72 6d 61 6c 2f 52 65 6d 6f 74 65 43 61 6d 65 72 61 41 63 74 69 76 69 74 79 } //1 camera/normal/RemoteCameraActivity
		$a_01_1 = {47 6d 61 69 6c 43 61 70 74 75 72 65 } //1 GmailCapture
		$a_01_2 = {45 78 65 63 53 70 6f 6f 66 53 6d 73 } //1 ExecSpoofSms
		$a_01_3 = {63 6f 6d 2f 66 70 2f 57 65 62 56 69 65 77 41 63 74 69 76 69 74 79 } //1 com/fp/WebViewActivity
		$a_01_4 = {6e 6d 67 6d 61 69 6c 2e 72 65 66 } //1 nmgmail.ref
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}