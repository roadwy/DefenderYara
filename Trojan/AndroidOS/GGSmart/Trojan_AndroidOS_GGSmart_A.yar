
rule Trojan_AndroidOS_GGSmart_A{
	meta:
		description = "Trojan:AndroidOS/GGSmart.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 73 79 73 74 65 6d 2f 61 70 70 2f 73 6d 61 72 74 63 6c 69 65 6e 74 2e 61 70 6b } //1 /system/app/smartclient.apk
		$a_01_1 = {66 61 6b 65 5f 61 70 70 5f 70 61 63 6b 61 67 65 5f 6e 61 6d 65 } //1 fake_app_package_name
		$a_01_2 = {69 74 27 73 20 6e 6f 74 20 32 2e 30 } //1 it's not 2.0
		$a_01_3 = {72 65 73 6f 75 72 63 65 73 2f 63 6f 6d 6d 6f 6e 73 2f 73 68 65 6c 6c 73 2e 7a 69 70 } //1 resources/commons/shells.zip
		$a_01_4 = {65 78 70 6c 6f 69 74 00 07 69 6e 73 74 61 6c 6c 00 0a 63 68 6d 6f 64 20 37 37 35 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}