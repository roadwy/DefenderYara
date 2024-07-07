
rule Trojan_Win32_Buzus_EB_MTB{
	meta:
		description = "Trojan:Win32/Buzus.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 00 6b 00 69 00 79 00 64 00 75 00 6f 00 6d 00 75 00 67 00 76 00 6d 00 74 00 71 00 72 00 65 00 73 00 76 00 75 00 67 00 6d 00 6d 00 6c 00 6f 00 65 00 7a 00 6a 00 } //1 ckiyduomugvmtqresvugmmloezj
		$a_01_1 = {41 00 63 00 65 00 72 00 62 00 61 00 74 00 65 00 } //1 Acerbate
		$a_01_2 = {76 6e 61 67 78 6e 77 67 72 62 } //1 vnagxnwgrb
		$a_01_3 = {61 63 63 69 64 65 6e 63 65 } //1 accidence
		$a_01_4 = {6d 65 6c 61 6e 63 68 6f 6c 69 61 63 } //1 melancholiac
		$a_01_5 = {6b 6f 6c 69 6e 73 6b 79 } //1 kolinsky
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}