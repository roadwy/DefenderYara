
rule TrojanSpy_AndroidOS_Mecor_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Mecor.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 6c 61 72 6d 2f 3f 66 72 6f 6d 5f 61 70 70 3d } //1 alarm/?from_app=
		$a_01_1 = {68 69 64 65 5f 67 70 73 5f 70 72 6f 67 72 65 73 73 } //1 hide_gps_progress
		$a_01_2 = {63 6f 63 6f 61 6d 2e 63 6f 2e 6b 72 2f 61 70 69 2f } //1 cocoam.co.kr/api/
		$a_01_3 = {61 6e 64 72 6f 69 64 5f 61 70 70 5f 63 68 65 63 6b 5f 75 73 65 72 5f 69 6e 66 6f } //1 android_app_check_user_info
		$a_02_4 = {63 6f 6d 2f [0-13] 2f [0-20] 2f 6d 61 69 6e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_02_4  & 1)*1) >=5
 
}