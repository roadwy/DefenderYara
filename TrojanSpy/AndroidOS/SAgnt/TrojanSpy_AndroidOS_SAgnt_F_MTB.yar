
rule TrojanSpy_AndroidOS_SAgnt_F_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {64 61 6c 62 61 6d 2e 76 69 70 } //01 00  dalbam.vip
		$a_00_1 = {76 33 2f 63 6f 6c 6c 65 63 74 2f 67 65 74 54 6f 6b 65 6e } //01 00  v3/collect/getToken
		$a_00_2 = {73 65 6e 64 43 61 6c 6c 6c 6f 67 73 } //01 00  sendCalllogs
		$a_00_3 = {73 65 6e 64 44 65 76 69 63 65 49 6e 66 6f 73 } //01 00  sendDeviceInfos
		$a_00_4 = {73 65 6e 64 41 64 64 72 65 73 73 62 6f 6f 6b 73 } //01 00  sendAddressbooks
		$a_00_5 = {67 65 74 57 65 62 53 6f 63 6b 65 74 43 6c 69 65 6e 74 } //00 00  getWebSocketClient
	condition:
		any of ($a_*)
 
}