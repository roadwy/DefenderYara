
rule TrojanSpy_AndroidOS_Pjapps_A{
	meta:
		description = "TrojanSpy:AndroidOS/Pjapps.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {3a 39 30 33 33 2f 90 02 07 2e 6c 6f 67 3f 69 64 3d 90 00 } //01 00 
		$a_03_1 = {3a 38 31 31 38 2f 70 75 73 68 2f 90 02 03 61 6e 64 72 6f 69 64 78 6d 6c 2f 90 00 } //01 00 
		$a_03_2 = {26 73 6f 66 74 69 64 3d 90 02 02 26 63 6e 3d 90 02 02 26 6e 74 3d 90 00 } //01 00 
		$a_01_3 = {2f 6d 6d 2e 64 6f 3f 69 6d 65 69 3d } //01 00  /mm.do?imei=
		$a_01_4 = {68 74 74 70 3a 2f 2f 78 78 78 78 78 78 78 78 78 39 3a 38 36 31 38 2f 63 6c 69 65 6e 74 2f 61 6e 64 72 6f 69 64 2f 61 2e 61 70 6b } //00 00  http://xxxxxxxxx9:8618/client/android/a.apk
	condition:
		any of ($a_*)
 
}