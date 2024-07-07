
rule Trojan_Win32_Ousaban_C{
	meta:
		description = "Trojan:Win32/Ousaban.C,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 05 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_81_1 = {23 4f 4e 2d 4c 49 4e 45 23 } //10 #ON-LINE#
		$a_81_2 = {23 73 74 72 50 69 6e 67 4f 6b 23 } //10 #strPingOk#
		$a_81_3 = {23 78 79 53 63 72 65 65 23 } //10 #xyScree#
		$a_81_4 = {23 73 74 72 49 6e 69 53 63 72 65 65 23 } //10 #strIniScree#
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*10+(#a_81_2  & 1)*10+(#a_81_3  & 1)*10+(#a_81_4  & 1)*10) >=41
 
}