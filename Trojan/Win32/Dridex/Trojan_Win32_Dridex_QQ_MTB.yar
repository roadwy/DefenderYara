
rule Trojan_Win32_Dridex_QQ_MTB{
	meta:
		description = "Trojan:Win32/Dridex.QQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {54 68 7e 73 20 70 35 67 67 72 36 69 20 63 36 6a 6e 6f 3b 20 62 65 } //Th~s p5ggr6i c6jno; be  3
		$a_80_1 = {27 62 72 61 2c 79 45 78 3f } //'bra,yEx?  3
		$a_80_2 = {4d 61 69 6c 41 73 53 6d 74 70 53 65 72 76 65 72 } //MailAsSmtpServer  3
		$a_80_3 = {55 70 6c 6f 61 64 56 69 61 48 74 74 70 } //UploadViaHttp  3
		$a_80_4 = {73 63 72 65 65 6e 73 68 6f 74 2e 70 6e 67 } //screenshot.png  3
		$a_80_5 = {49 4f 62 69 74 } //IObit  3
		$a_80_6 = {53 63 72 53 68 6f 74 5a 69 70 } //ScrShotZip  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}