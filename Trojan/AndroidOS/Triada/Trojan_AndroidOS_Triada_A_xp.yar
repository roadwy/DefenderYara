
rule Trojan_AndroidOS_Triada_A_xp{
	meta:
		description = "Trojan:AndroidOS/Triada.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 73 79 73 74 65 6d 2f 61 70 70 2f 25 73 2f 25 73 2e 61 70 6b } //1 /system/app/%s/%s.apk
		$a_01_1 = {74 6f 6f 6c 62 6f 78 20 63 68 61 74 74 72 20 2d 69 61 41 20 25 73 } //1 toolbox chattr -iaA %s
		$a_01_2 = {62 75 73 79 62 6f 78 20 63 68 61 74 74 72 20 2d 69 61 41 20 25 73 } //1 busybox chattr -iaA %s
		$a_01_3 = {2f 64 61 74 61 2f 6c 6f 63 61 6c 2f 74 6d 70 2f 2e 6c 6f 63 61 6c 74 6d 70 74 65 73 74 2e 61 70 6b } //1 /data/local/tmp/.localtmptest.apk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}