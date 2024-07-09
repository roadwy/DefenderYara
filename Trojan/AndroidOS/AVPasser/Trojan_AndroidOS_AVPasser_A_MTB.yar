
rule Trojan_AndroidOS_AVPasser_A_MTB{
	meta:
		description = "Trojan:AndroidOS/AVPasser.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_02_0 = {72 6d 20 2d 72 20 2f 73 79 73 74 65 6d 2f 61 70 70 2f [0-06] 2e 61 70 6b } //1
		$a_00_1 = {72 6d 20 2d 72 20 2f 73 79 73 74 65 6d 2f 73 75 } //1 rm -r /system/su
		$a_00_2 = {63 68 6d 6f 64 20 37 37 37 20 2f 73 79 73 74 65 6d 2f 78 62 69 6e 2f 73 75 } //1 chmod 777 /system/xbin/su
		$a_00_3 = {61 6d 20 66 6f 72 63 65 2d 73 74 6f 70 20 63 6f 6d 2e 61 6e 74 69 76 69 72 75 73 } //1 am force-stop com.antivirus
		$a_00_4 = {75 6e 69 6e 73 74 61 6c 6c 20 61 70 6b } //1 uninstall apk
		$a_00_5 = {6f 70 65 6e 20 63 61 6c 6c 20 72 65 63 6f 72 64 20 66 75 6e 63 74 69 6f 6e } //1 open call record function
		$a_00_6 = {43 61 6c 6c 4c 6f 67 4f 62 73 65 72 76 65 72 } //1 CallLogObserver
		$a_00_7 = {43 61 6d 65 72 61 20 74 61 6b 65 5f 70 69 63 } //1 Camera take_pic
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=6
 
}