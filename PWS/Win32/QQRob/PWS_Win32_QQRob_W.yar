
rule PWS_Win32_QQRob_W{
	meta:
		description = "PWS:Win32/QQRob.W,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 02 6a 00 6a fc 57 e8 90 01 03 ff 6a 00 8d 45 f0 50 6a 04 53 57 e8 90 01 03 ff 81 33 7d a0 86 59 6a 00 57 e8 90 01 03 ff 3b 03 0f 86 90 01 02 00 00 6a 02 6a 00 90 00 } //1
		$a_03_1 = {6a 02 6a 00 6a fc 57 e8 90 01 03 ff 6a 00 8d 45 f0 50 6a 04 53 57 e8 90 01 03 ff 81 33 90 01 04 6a 00 57 e8 90 01 03 ff 3b 03 0f 86 90 01 02 00 00 6a 02 6a 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}