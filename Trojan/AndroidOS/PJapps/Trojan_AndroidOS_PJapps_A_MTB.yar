
rule Trojan_AndroidOS_PJapps_A_MTB{
	meta:
		description = "Trojan:AndroidOS/PJapps.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 74 65 73 74 2e 73 6d 73 2e 73 65 6e 64 } //01 00  com.test.sms.send
		$a_01_1 = {2f 6d 6d 2e 64 6f 3f 69 6d 65 69 3d } //01 00  /mm.do?imei=
		$a_01_2 = {2f 73 64 63 61 72 64 2f 61 6e 64 72 6f 69 64 68 2e 6c 6f 67 } //01 00  /sdcard/androidh.log
		$a_01_3 = {54 41 4e 43 41 63 74 69 76 69 74 79 } //00 00  TANCActivity
	condition:
		any of ($a_*)
 
}