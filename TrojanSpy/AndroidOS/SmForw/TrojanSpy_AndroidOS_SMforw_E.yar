
rule TrojanSpy_AndroidOS_SMforw_E{
	meta:
		description = "TrojanSpy:AndroidOS/SMforw.E,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 52 4e 75 6d 4e 43 7c 2a 7c } //1 GRNumNC|*|
		$a_00_1 = {53 45 4e 44 5f 53 4d 53 5f 4e 55 4d } //1 SEND_SMS_NUM
		$a_00_2 = {43 4f 4e 4e 45 43 54 5f 53 55 43 43 45 45 44 } //1 CONNECT_SUCCEED
		$a_01_3 = {43 67 44 61 74 61 7c 2a 7c } //1 CgData|*|
		$a_01_4 = {63 6f 6e 4d 61 6e } //1 conMan
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}