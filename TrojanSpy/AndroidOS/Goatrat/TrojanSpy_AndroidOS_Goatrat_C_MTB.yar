
rule TrojanSpy_AndroidOS_Goatrat_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Goatrat.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 68 6d 64 6d 2e 72 65 6d 6f 74 65 73 65 72 76 69 63 65 } //1 com.hmdm.remoteservice
		$a_01_1 = {41 43 54 49 4f 4e 5f 53 43 52 45 45 4e 5f 53 48 41 52 49 4e 47 5f 50 45 52 4d 49 53 53 49 4f 4e 5f 4e 45 45 44 45 44 } //1 ACTION_SCREEN_SHARING_PERMISSION_NEEDED
		$a_01_2 = {45 58 54 52 41 5f 57 45 42 52 54 43 55 50 } //1 EXTRA_WEBRTCUP
		$a_01_3 = {74 65 73 74 5f 73 72 63 5f 69 70 } //1 test_src_ip
		$a_01_4 = {2f 72 65 73 74 2f 70 6c 75 67 69 6e 73 2f 61 70 75 70 70 65 74 2f 70 75 62 6c 69 63 2f 73 65 73 73 69 6f 6e } //1 /rest/plugins/apuppet/public/session
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}