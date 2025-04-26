
rule TrojanSpy_AndroidOS_Fakecalls_L_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Fakecalls.L!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 61 70 69 2f 61 70 70 6c 69 6e 6b 2f 72 65 71 75 65 73 74 6d 61 69 6e 63 61 6c 6c } //1 /api/applink/requestmaincall
		$a_00_1 = {2f 61 70 69 2f 6d 6f 62 69 6c 65 2f 6d 6f 62 69 6c 65 5f 69 6e 66 6f } //1 /api/mobile/mobile_info
		$a_00_2 = {6b 65 79 5f 6f 72 69 67 69 6e 5f 70 61 63 6b 61 67 65 5f 6e 61 6d 65 } //1 key_origin_package_name
		$a_00_3 = {63 68 6f 6e 67 70 61 6e } //1 chongpan
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}