
rule TrojanSpy_AndroidOS_BajaSpy_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/BajaSpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 73 65 72 76 6c 65 74 2f 53 65 6e 64 4d 61 73 73 61 67 65 } //05 00  /servlet/SendMassage
		$a_01_1 = {6b 6b 2f 63 68 75 6e 79 75 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //01 00  kk/chunyu/MainActivity
		$a_01_2 = {6d 79 62 61 6e 6b } //01 00  mybank
		$a_01_3 = {2f 73 79 73 74 65 6d 2f 61 70 70 2f 73 75 70 65 72 75 73 65 72 2e 61 70 6b } //01 00  /system/app/superuser.apk
		$a_01_4 = {73 6e 65 64 50 68 6f 6e 65 } //01 00  snedPhone
		$a_01_5 = {53 4d 53 4f 62 73 65 72 76 65 72 } //00 00  SMSObserver
	condition:
		any of ($a_*)
 
}