
rule Trojan_AndroidOS_Dvmap_A_xp{
	meta:
		description = "Trojan:AndroidOS/Dvmap.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 64 61 74 61 2f 6c 6f 63 61 6c 2f 74 6d 70 2f 2e 6c 6f 63 61 6c 74 6d 70 74 65 73 74 2e 61 70 6b } //1 /data/local/tmp/.localtmptest.apk
		$a_01_1 = {2f 73 79 73 74 65 6d 2f 78 62 69 6e 2f 62 75 73 79 62 6f 78 } //1 /system/xbin/busybox
		$a_01_2 = {2f 6d 6e 74 2f 73 65 63 75 72 65 2f 61 73 65 63 2f 73 6d 64 6c 32 74 6d 70 31 2e 61 73 65 63 } //1 /mnt/secure/asec/smdl2tmp1.asec
		$a_01_3 = {2f 73 79 73 74 65 6d 2f 65 74 63 2f 69 6e 73 74 61 6c 6c 5f 72 65 63 6f 76 65 72 79 2e 73 68 } //1 /system/etc/install_recovery.sh
		$a_01_4 = {64 61 74 61 2f 6c 6f 63 61 6c 2f 74 6d 70 2f 61 6e 64 72 6f 69 64 5f 69 63 63 64 2e 74 78 74 } //1 data/local/tmp/android_iccd.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}