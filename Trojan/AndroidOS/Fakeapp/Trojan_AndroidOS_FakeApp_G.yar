
rule Trojan_AndroidOS_FakeApp_G{
	meta:
		description = "Trojan:AndroidOS/FakeApp.G,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_00_0 = {76 69 70 2f 68 35 3f 70 6c 61 74 3d 61 6e 64 72 6f 69 64 } //2 vip/h5?plat=android
		$a_00_1 = {77 65 62 61 6e 64 72 6f 69 64 5f 69 73 66 69 72 73 74 5f 65 6e 63 6f 6d 65 } //2 webandroid_isfirst_encome
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2) >=4
 
}