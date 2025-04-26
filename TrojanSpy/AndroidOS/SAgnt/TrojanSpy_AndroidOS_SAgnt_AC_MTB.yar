
rule TrojanSpy_AndroidOS_SAgnt_AC_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.AC!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6f 72 64 65 72 5f 70 61 79 5f 6b 63 70 } //1 order_pay_kcp
		$a_01_1 = {61 70 70 5f 6c 6f 67 69 6e 2e 63 6d } //1 app_login.cm
		$a_01_2 = {67 70 73 5f 68 69 64 65 } //1 gps_hide
		$a_01_3 = {26 41 70 70 55 72 6c 3d 63 6d 5f 6b 63 70 3a 2f 2f } //1 &AppUrl=cm_kcp://
		$a_01_4 = {63 61 6c 6c 48 69 64 64 65 6e 57 65 62 56 69 65 77 4d 65 74 68 6f 64 } //1 callHiddenWebViewMethod
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}