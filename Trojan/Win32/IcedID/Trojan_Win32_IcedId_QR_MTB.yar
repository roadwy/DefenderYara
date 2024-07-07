
rule Trojan_Win32_IcedId_QR_MTB{
	meta:
		description = "Trojan:Win32/IcedId.QR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {44 6c 65 69 74 72 65 76 72 44 6c 6e 65 69 74 72 65 76 72 50 75 65 } //DleitrevrDlneitrevrPue  3
		$a_80_1 = {74 70 65 76 72 53 73 65 64 65 76 72 } //tpevrSsedevr  3
		$a_80_2 = {30 53 72 75 41 4b 53 72 70 41 4c 53 72 70 57 4b 52 45 33 } //0SruAKSrpALSrpWKRE3  3
		$a_80_3 = {6f 70 6a 5f 63 6f 64 65 63 5f 73 65 74 5f 74 68 72 65 61 64 73 } //opj_codec_set_threads  3
		$a_80_4 = {52 65 73 75 6d 65 53 65 72 76 65 72 } //ResumeServer  3
		$a_80_5 = {53 74 61 72 74 53 65 72 76 65 72 } //StartServer  3
		$a_80_6 = {53 74 6f 70 53 65 72 76 65 72 } //StopServer  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}