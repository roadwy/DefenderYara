
rule Trojan_AndroidOS_BaseBridge_gen_A{
	meta:
		description = "Trojan:AndroidOS/BaseBridge.gen!A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 02 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 78 78 2e 61 70 6b } //01 00  xxx.apk
		$a_00_1 = {61 6e 53 65 72 76 65 72 42 } //01 00  anServerB
		$a_00_2 = {61 6e 53 65 72 76 65 72 42 2e 73 6f } //01 00  anServerB.so
		$a_01_3 = {65 48 68 34 4c 6d 46 77 61 77 3d 3d } //01 00  eHh4LmFwaw==
		$a_01_4 = {59 57 35 54 5a 58 4a 32 5a 58 4a 43 4c 6e 4e 76 } //01 00  YW5TZXJ2ZXJCLnNv
		$a_01_5 = {53 4d 53 41 70 70 2e 61 70 6b } //01 00  SMSApp.apk
		$a_01_6 = {67 6c 6f 62 61 6c 5f 62 5f 76 65 72 73 69 6f 6e 5f 69 64 } //01 00  global_b_version_id
		$a_01_7 = {47 6f 74 20 70 72 6f 63 65 73 73 69 64 3a } //01 00  Got processid:
		$a_01_8 = {66 69 72 73 74 5f 61 70 70 5f 70 65 72 66 65 72 65 6e 63 65 73 } //01 00  first_app_perferences
		$a_00_9 = {61 5f 42 53 65 72 76 65 72 33 } //01 00  a_BServer3
		$a_01_10 = {68 61 73 42 52 75 6e 69 6e 67 } //01 00  hasBRuning
		$a_01_11 = {37 78 42 4e 7a 4b 46 43 7a 4b 46 57 } //00 00  7xBNzKFCzKFW
	condition:
		any of ($a_*)
 
}