
rule Trojan_AndroidOS_SmsSpy_N_MTB{
	meta:
		description = "Trojan:AndroidOS/SmsSpy.N!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 61 6c 6c 73 65 72 76 69 63 65 63 65 6e 74 65 72 2f 61 6e 64 72 6f 69 64 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //02 00  com/allservicecenter/android/MainActivity
		$a_00_1 = {63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 61 6e 64 72 6f 69 64 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //02 00  com/example/android/MainActivity
		$a_01_2 = {4d 73 52 65 63 65 69 76 65 72 } //01 00  MsReceiver
		$a_01_3 = {61 6c 6c 50 65 72 6d 69 73 73 69 6f 6e 73 47 72 61 6e 74 65 64 } //01 00  allPermissionsGranted
		$a_01_4 = {73 65 6e 64 44 61 74 61 } //00 00  sendData
	condition:
		any of ($a_*)
 
}