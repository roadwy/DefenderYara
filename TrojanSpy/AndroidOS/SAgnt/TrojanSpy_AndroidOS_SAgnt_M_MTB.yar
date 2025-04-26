
rule TrojanSpy_AndroidOS_SAgnt_M_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.M!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 44 65 76 69 63 65 53 65 72 69 61 6c 4d 44 35 } //1 getDeviceSerialMD5
		$a_01_1 = {6d 79 42 74 6e 4d 73 67 } //1 myBtnMsg
		$a_01_2 = {69 73 4d 6f 62 69 6c 65 4e 4f } //1 isMobileNO
		$a_01_3 = {64 65 6c 65 74 65 53 4d 53 } //1 deleteSMS
		$a_01_4 = {63 6f 6d 2e 71 69 68 75 33 36 30 2e 6d 79 6c 69 76 65 } //1 com.qihu360.mylive
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}