
rule TrojanSpy_AndroidOS_Slrat_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Slrat.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 73 6c 68 34 63 6b 33 72 2e 73 6c 72 61 74 } //1 com.slh4ck3r.slrat
		$a_01_1 = {64 65 76 69 63 65 5f 61 64 6d 69 6e 5f 64 69 73 61 62 6c 65 64 } //1 device_admin_disabled
		$a_00_2 = {2f 73 79 73 74 65 6d 2f 61 70 70 2f 63 6f 6d 2e 73 6c 68 34 63 6b 33 72 2e 73 6c 72 61 74 2e 61 70 6b } //1 /system/app/com.slh4ck3r.slrat.apk
		$a_00_3 = {53 4c 5f 48 34 43 4b 33 52 } //1 SL_H4CK3R
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}