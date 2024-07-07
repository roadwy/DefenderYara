
rule Trojan_AndroidOS_RemRat_A{
	meta:
		description = "Trojan:AndroidOS/RemRat.A,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_00_0 = {4c 72 65 6d 2f 63 6f 6d 70 61 6e 79 2f 63 6f 6d 2f 72 65 6d 2f 54 61 73 6b 73 2f 53 45 2f 56 69 62 65 72 61 74 69 6f 6e } //2 Lrem/company/com/rem/Tasks/SE/Viberation
		$a_00_1 = {2f 2e 70 68 6f 74 6f 73 2f } //2 /.photos/
		$a_00_2 = {2f 2e 63 61 6c 6c 73 2f } //2 /.calls/
		$a_00_3 = {2f 73 79 73 74 65 6d 2f 61 70 70 2f 53 75 70 65 72 75 73 65 72 2e 61 70 6b } //1 /system/app/Superuser.apk
		$a_00_4 = {2f 64 61 74 61 2f 6c 6f 63 61 6c 2f 78 62 69 6e 2f 73 75 } //1 /data/local/xbin/su
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=7
 
}