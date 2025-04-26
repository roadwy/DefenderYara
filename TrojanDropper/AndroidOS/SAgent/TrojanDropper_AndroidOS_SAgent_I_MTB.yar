
rule TrojanDropper_AndroidOS_SAgent_I_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/SAgent.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 61 73 73 65 74 65 78 61 6d } //1 Lcom/example/assetexam
		$a_01_1 = {63 6f 6d 2e 76 71 73 2e 69 70 68 6f 6e 65 61 73 73 65 73 73 } //1 com.vqs.iphoneassess
		$a_01_2 = {2f 6d 6e 74 2f 73 64 63 61 72 64 2f 56 71 73 50 68 6f 6e 65 2e 61 70 6b } //1 /mnt/sdcard/VqsPhone.apk
		$a_01_3 = {69 73 41 70 70 49 6e 73 74 61 6c 6c } //1 isAppInstall
		$a_01_4 = {63 6f 70 79 41 70 6b 46 72 6f 6d 41 73 73 65 74 73 } //1 copyApkFromAssets
		$a_01_5 = {52 75 6e 73 74 61 72 74 } //1 Runstart
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}