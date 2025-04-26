
rule TrojanSpy_AndroidOS_Basbanke_E_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Basbanke.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {66 61 6b 65 70 69 6e 5f 61 63 74 69 76 69 74 79 } //1 fakepin_activity
		$a_00_1 = {67 65 74 70 61 73 73 61 63 74 69 76 69 74 79 } //1 getpassactivity
		$a_00_2 = {63 6f 6d 2e 61 6e 64 72 6f 69 64 2e 70 61 63 6b 61 67 65 69 6e 73 74 61 6c 6c 65 72 3a 69 64 2f 70 65 72 6d 69 73 73 69 6f 6e 5f 61 6c 6c 6f 77 5f 62 75 74 74 6f 6e } //1 com.android.packageinstaller:id/permission_allow_button
		$a_00_3 = {69 6e 6a 65 63 74 5f 61 63 74 69 76 69 74 79 } //1 inject_activity
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}