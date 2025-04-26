
rule Trojan_AndroidOS_Smsthief_A{
	meta:
		description = "Trojan:AndroidOS/Smsthief.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {3f 70 61 73 73 3d 61 70 70 31 36 38 26 63 6d 64 3d 73 6d 73 26 73 69 64 3d 25 31 24 73 26 73 6d 73 3d 25 32 24 73 } //2 ?pass=app168&cmd=sms&sid=%1$s&sms=%2$s
		$a_01_1 = {2f 2f 73 67 62 78 2e 6f 6e 6c 69 6e 65 } //2 //sgbx.online
		$a_01_2 = {4d 79 52 65 63 69 65 76 65 72 } //2 MyReciever
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}