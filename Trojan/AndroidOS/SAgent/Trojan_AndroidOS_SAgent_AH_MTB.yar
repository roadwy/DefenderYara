
rule Trojan_AndroidOS_SAgent_AH_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgent.AH!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 73 79 73 74 65 6d 2f 61 70 70 2f 73 65 72 76 69 63 65 2e 61 70 6b } //01 00  /system/app/service.apk
		$a_00_1 = {70 75 74 41 70 6b 54 6f 53 79 73 74 65 6d } //01 00  putApkToSystem
		$a_00_2 = {64 65 6c 46 69 6c 65 49 66 45 78 69 73 74 } //01 00  delFileIfExist
		$a_00_3 = {64 6f 53 74 68 42 79 53 75 } //01 00  doSthBySu
		$a_00_4 = {53 63 72 65 65 6e 43 61 70 74 75 72 65 41 63 74 69 76 69 74 79 } //01 00  ScreenCaptureActivity
		$a_00_5 = {49 6e 73 74 61 6c 6c 54 68 69 72 64 41 70 70 } //01 00  InstallThirdApp
		$a_02_6 = {61 6d 20 73 74 61 72 74 73 65 72 76 69 63 65 90 02 15 2d 6e 90 02 25 2f 2e 50 6f 77 65 72 44 65 74 65 63 74 53 65 72 76 69 63 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}