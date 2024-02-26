
rule Trojan_AndroidOS_FakeInst_K_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeInst.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 6f 69 6e 6d 6f 62 69 6c 2e 72 75 } //01 00  joinmobil.ru
		$a_01_1 = {2f 73 74 61 74 73 2f 61 64 76 2e 70 68 70 20 71 73 74 73 7a 64 3d } //01 00  /stats/adv.php qstszd=
		$a_01_2 = {63 68 65 63 6b 63 6f 6d 61 6e 64 } //01 00  checkcomand
		$a_01_3 = {61 6e 64 72 6f 69 64 2e 74 65 6c 65 70 68 6f 6e 79 2e 67 73 6d 2e 53 6d 73 4d 61 6e 61 67 65 72 } //01 00  android.telephony.gsm.SmsManager
		$a_01_4 = {72 65 75 6c 74 75 72 6c } //00 00  reulturl
	condition:
		any of ($a_*)
 
}
rule Trojan_AndroidOS_FakeInst_K_MTB_2{
	meta:
		description = "Trojan:AndroidOS/FakeInst.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {6b 69 6c 6c 50 72 6f 63 65 73 73 } //02 00  killProcess
		$a_03_1 = {12 04 23 71 90 01 01 02 28 02 b0 26 8d 62 4f 02 01 04 d8 05 05 01 d8 04 04 01 33 74 90 02 05 12 02 70 30 90 02 05 10 02 6e 10 90 02 05 00 00 0c 00 11 00 48 02 03 05 90 00 } //02 00 
		$a_03_2 = {12 f4 da 08 08 04 d8 08 08 01 62 05 c0 05 22 00 01 02 23 81 5d 02 d8 08 08 ff 90 02 05 91 02 06 02 d8 06 02 fe d8 04 04 01 8d 62 4f 02 01 04 33 84 90 02 05 12 02 70 30 90 02 05 10 02 11 00 d8 07 07 01 48 02 05 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}