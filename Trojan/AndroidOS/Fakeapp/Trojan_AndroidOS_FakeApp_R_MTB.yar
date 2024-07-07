
rule Trojan_AndroidOS_FakeApp_R_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeApp.R!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 74 70 73 3a 2f 2f 61 70 6b 61 66 65 2e 63 6f 6d 2f 70 72 6f 64 75 63 74 2f 6d 69 6e 65 63 72 61 66 74 2f } //1 ttps://apkafe.com/product/minecraft/
		$a_01_1 = {63 6f 6d 2f 72 65 70 6f 72 74 2f 6d 79 61 70 } //1 com/report/myap
		$a_01_2 = {52 6f 6d 69 43 6c 69 65 6e 74 } //1 RomiClient
		$a_01_3 = {2f 6d 69 6e 65 63 72 61 66 74 2d 72 6f 6d 61 6e 69 2d 67 67 2d 75 70 64 61 74 65 2e 61 70 6b } //1 /minecraft-romani-gg-update.apk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}