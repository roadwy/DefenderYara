
rule TrojanDropper_AndroidOS_SAgnt_S_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/SAgnt.S!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 70 20 2f 73 64 63 61 72 64 2f 7a 69 68 61 6f 2e 6c 20 2f 73 79 73 74 65 6d 2f 61 70 70 2f } //1 cp /sdcard/zihao.l /system/app/
		$a_01_1 = {63 68 6d 6f 64 20 36 34 34 20 2f 73 79 73 74 65 6d 2f 61 70 70 2f 7a 69 68 61 6f 2e 61 70 6b } //1 chmod 644 /system/app/zihao.apk
		$a_01_2 = {63 68 65 63 6b 52 6f 6f 74 50 65 72 6d 69 73 73 69 6f 6e } //1 checkRootPermission
		$a_01_3 = {72 6f 6f 74 53 68 65 6c 6c } //1 rootShell
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}