
rule TrojanSpy_AndroidOS_FakeCalls_K_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeCalls.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_00_0 = {76 69 64 65 6f 63 6c 6f 75 64 2e 63 6e 2d 68 61 6e 67 7a 68 6f 75 2e 6c 6f 67 2e 61 6c 69 79 75 6e 63 73 2e 63 6f 6d } //1 videocloud.cn-hangzhou.log.aliyuncs.com
		$a_00_1 = {43 61 6c 6c 20 69 73 20 68 6f 6f 6b 65 64 } //1 Call is hooked
		$a_00_2 = {6f 6e 53 74 61 72 74 43 6f 6d 6d 61 6e 64 } //1 onStartCommand
		$a_00_3 = {64 65 6c 65 74 65 53 4d 53 } //1 deleteSMS
		$a_00_4 = {4b 45 59 5f 45 4d 41 49 4c 53 } //1 KEY_EMAILS
		$a_00_5 = {4b 45 59 5f 54 45 4c 45 43 4f 4d 53 5f 4e 41 4d 45 31 } //1 KEY_TELECOMS_NAME1
		$a_00_6 = {4b 45 59 5f 55 50 4c 4f 41 44 5f 31 } //1 KEY_UPLOAD_1
		$a_00_7 = {4b 45 59 5f 52 45 43 56 5f 46 } //1 KEY_RECV_F
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=7
 
}