
rule TrojanSpy_AndroidOS_FakeCalls_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeCalls.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 64 65 76 69 63 65 2f 67 65 74 74 72 61 6e 73 66 65 72 3f 6e 75 6d 62 65 72 3d } //01 00  /device/gettransfer?number=
		$a_00_1 = {2f 64 65 76 69 63 65 2f 67 65 74 6e 75 6d 62 65 72 3f 6e 75 6d 62 65 72 3d } //01 00  /device/getnumber?number=
		$a_00_2 = {2f 64 65 76 69 63 65 2f 64 65 76 69 63 65 65 6e 64 63 61 6c 6c 3f 69 6d 65 69 3d } //01 00  /device/deviceendcall?imei=
		$a_00_3 = {26 69 73 53 74 61 72 74 3d 74 72 75 65 26 6e 61 6d 65 3d } //01 00  &isStart=true&name=
		$a_00_4 = {75 70 6c 6f 61 64 5f 63 6f 6e 74 72 61 63 74 73 } //01 00  upload_contracts
		$a_00_5 = {75 70 6c 6f 61 64 5f 73 6d 73 } //01 00  upload_sms
		$a_00_6 = {64 65 6c 65 74 65 5f 63 61 6c 6c 6c 6f 67 } //00 00  delete_calllog
	condition:
		any of ($a_*)
 
}