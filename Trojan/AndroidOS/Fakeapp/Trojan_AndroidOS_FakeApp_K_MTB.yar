
rule Trojan_AndroidOS_FakeApp_K_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeApp.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 77 61 67 64 2f 67 67 2f 4d 79 53 65 72 76 69 63 65 3b } //2 Lcom/wagd/gg/MyService;
		$a_00_1 = {2f 75 70 64 61 74 65 2f 75 70 64 61 74 65 2e 63 6f 6e 66 } //2 /update/update.conf
		$a_00_2 = {6c 6f 61 64 36 34 44 61 74 61 20 62 79 74 65 73 } //1 load64Data bytes
		$a_00_3 = {67 65 74 54 68 69 73 41 70 70 41 72 63 68 } //1 getThisAppArch
		$a_00_4 = {4d 6f 62 63 6c 69 63 6b 52 54 } //1 MobclickRT
		$a_00_5 = {2f 73 79 73 74 65 6d 2f 61 70 70 2f 4b 69 6e 67 75 73 65 72 2e 61 70 6b } //1 /system/app/Kinguser.apk
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}