
rule Trojan_AndroidOS_Rootnik_E{
	meta:
		description = "Trojan:AndroidOS/Rootnik.E,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {78 78 20 55 70 6c 6f 61 64 20 44 65 76 69 63 65 20 74 6f 20 73 65 72 76 65 72 20 73 74 61 72 74 } //2 xx Upload Device to server start
		$a_01_1 = {2f 6d 6e 74 2f 65 78 74 73 64 63 61 72 64 2f 61 6e 64 72 6f 69 64 5f 61 64 5f 74 72 61 63 65 2e 6c 6f 67 } //2 /mnt/extsdcard/android_ad_trace.log
		$a_01_2 = {73 75 62 5f 6a 63 5f 76 30 32 2e 61 70 6b } //2 sub_jc_v02.apk
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}