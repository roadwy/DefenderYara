
rule Trojan_AndroidOS_DroidKrungFu_B{
	meta:
		description = "Trojan:AndroidOS/DroidKrungFu.B,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 73 79 73 74 65 6d 2f 62 69 6e 2f 63 68 6d 6f 64 20 37 35 35 20 2f 73 79 73 74 65 6d 2f 62 69 6e 2f 62 75 73 79 62 6f 78 } //1 /system/bin/chmod 755 /system/bin/busybox
		$a_01_1 = {2f 57 65 62 56 69 65 77 2e 64 62 } //1 /WebView.db
		$a_01_2 = {2f 73 79 73 74 65 6d 2f 65 74 63 2f 2e 72 69 6c 64 5f 63 66 67 } //1 /system/etc/.rild_cfg
		$a_01_3 = {2f 73 65 63 62 69 6e 6f } //1 /secbino
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}