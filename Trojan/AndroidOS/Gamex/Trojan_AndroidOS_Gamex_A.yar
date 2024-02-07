
rule Trojan_AndroidOS_Gamex_A{
	meta:
		description = "Trojan:AndroidOS/Gamex.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 75 69 6c 64 43 6f 6e 66 69 67 2e 6a 61 76 61 } //01 00  BuildConfig.java
		$a_01_1 = {54 61 72 67 65 74 41 70 69 2e 6a 61 76 61 } //01 00  TargetApi.java
		$a_01_2 = {69 6e 70 75 74 65 78 2f 69 6e 64 65 78 2e 70 68 70 3f 73 3d 2f 49 6e 74 65 72 66 61 63 65 2f 6e 65 69 69 6e 74 65 72 } //00 00  inputex/index.php?s=/Interface/neiinter
	condition:
		any of ($a_*)
 
}
rule Trojan_AndroidOS_Gamex_A_2{
	meta:
		description = "Trojan:AndroidOS/Gamex.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 68 6d 6f 64 20 36 34 34 20 2f 73 79 73 74 65 6d 2f 61 70 70 2f 43 6f 6d 41 6e 64 72 6f 69 64 53 65 74 74 69 6e 67 2e 61 70 6b } //01 00  chmod 644 /system/app/ComAndroidSetting.apk
		$a_01_1 = {67 61 6d 65 78 2f 69 6e 73 65 74 2f 42 75 69 6c 64 43 6f 6e 66 69 67 } //01 00  gamex/inset/BuildConfig
		$a_01_2 = {6c 6f 67 6f 73 2e 70 6e 67 } //00 00  logos.png
	condition:
		any of ($a_*)
 
}