
rule Trojan_AndroidOS_FakeInst_L_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeInst.L!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {63 6f 6d 2f 63 61 69 61 70 70 2f 73 6b 79 70 65 90 02 20 4d 61 69 6e 41 63 74 69 76 69 74 79 90 00 } //01 00 
		$a_03_1 = {63 6f 6d 2f 6d 6f 62 69 61 64 73 2f 69 6e 73 74 61 6c 6c 65 72 2f 90 02 20 4d 61 69 6e 41 63 74 69 76 69 74 79 90 00 } //01 00 
		$a_01_2 = {68 74 74 70 3a 2f 2f 61 2e 74 61 69 67 61 6d 65 6d 6f 62 69 6c 65 68 61 79 2e 6e 65 74 2f 6d 6f 2d 6b 68 2e 70 68 70 3f 61 70 70 3d } //01 00  http://a.taigamemobilehay.net/mo-kh.php?app=
		$a_03_3 = {68 74 74 70 3a 2f 2f 90 01 01 2e 74 61 69 67 61 6d 65 6d 6f 62 69 6c 65 68 61 79 2e 6e 65 74 90 02 10 2f 6d 6f 2d 6b 68 2e 6a 73 70 3f 61 70 70 3d 90 00 } //01 00 
		$a_01_4 = {76 6e 2f 6d 77 6f 72 6b 2f 61 6e 64 72 6f 69 64 2f 6d 68 75 62 6d 61 6e 61 67 65 72 2f 4d 48 75 62 4d 61 6e 61 67 65 72 } //01 00  vn/mwork/android/mhubmanager/MHubManager
		$a_01_5 = {55 52 4c 5f 49 4e 53 54 41 4c 4c } //01 00  URL_INSTALL
		$a_01_6 = {6b 69 6c 6c 50 72 6f 63 65 73 73 } //00 00  killProcess
	condition:
		any of ($a_*)
 
}