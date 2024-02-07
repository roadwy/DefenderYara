
rule TrojanDropper_AndroidOS_Shedun_A_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Shedun.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 12 03 21 04 6e 40 90 01 04 12 03 90 02 04 6e 40 90 01 04 21 03 35 31 11 00 48 03 00 01 90 01 04 48 04 02 04 b7 43 8d 33 4f 03 00 01 d8 01 01 01 28 f1 0d 00 12 00 11 00 90 00 } //01 00 
		$a_01_1 = {12 67 65 74 41 70 70 6c 69 63 61 74 69 6f 6e 49 6e 66 6f 00 09 67 65 74 41 73 73 65 74 73 00 0e 67 65 74 43 6c 61 73 73 4c 6f 61 64 65 72 00 10 67 65 74 44 65 63 6c 61 72 65 64 46 69 65 6c 64 00 } //01 00 
		$a_01_2 = {61 6e 64 72 6f 69 64 2e 61 70 70 2e 4c 6f 61 64 65 64 41 70 6b } //00 00  android.app.LoadedApk
	condition:
		any of ($a_*)
 
}