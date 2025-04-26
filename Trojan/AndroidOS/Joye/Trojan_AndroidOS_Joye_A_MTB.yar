
rule Trojan_AndroidOS_Joye_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Joye.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {67 6c 6f 62 61 6c 70 61 79 72 65 63 6f 72 64 2f 72 65 63 6f 72 64 2f 72 65 63 6f 72 64 2e 70 68 70 } //1 globalpayrecord/record/record.php
		$a_01_1 = {70 61 79 64 61 74 61 3d } //1 paydata=
		$a_01_2 = {73 6d 73 43 6f 64 65 4d 65 73 73 61 67 65 } //1 smsCodeMessage
		$a_01_3 = {73 65 6e 64 54 65 78 74 4d 65 73 73 61 67 65 4d 74 6b } //1 sendTextMessageMtk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}