
rule Trojan_AndroidOS_Opfake_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Opfake.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 64 65 76 2f 67 65 74 54 61 73 6b 2e 70 68 70 } //01 00  /dev/getTask.php
		$a_01_1 = {61 6e 64 72 70 61 79 2e 72 75 } //01 00  andrpay.ru
		$a_01_2 = {63 6f 6d 2f 61 70 69 72 65 66 6c 65 63 74 69 6f 6e 6d 61 6e 61 67 65 72 } //01 00  com/apireflectionmanager
		$a_01_3 = {63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 73 79 73 74 65 6d 2f 41 70 70 44 6f 77 6e 6c 6f 61 64 65 72 41 63 74 69 76 69 74 79 } //00 00  com/android/system/AppDownloaderActivity
	condition:
		any of ($a_*)
 
}