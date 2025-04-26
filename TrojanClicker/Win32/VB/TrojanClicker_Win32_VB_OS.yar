
rule TrojanClicker_Win32_VB_OS{
	meta:
		description = "TrojanClicker:Win32/VB.OS,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6e 00 65 00 78 00 6f 00 61 00 2e 00 63 00 6f 00 6d 00 2f 00 72 00 61 00 6e 00 6b 00 62 00 6f 00 6f 00 73 00 74 00 2e 00 70 00 68 00 70 00 } //1 http://nexoa.com/rankboost.php
	condition:
		((#a_01_0  & 1)*1) >=1
 
}