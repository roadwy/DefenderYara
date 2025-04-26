
rule TrojanSpy_AndroidOS_Fakecall_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Fakecall.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 73 70 79 73 73 2e 6d 6f 62 69 6c 65 68 61 72 64 77 61 72 65 2e 64 62 2e 53 6d 73 49 74 65 6d } //2 com.spyss.mobilehardware.db.SmsItem
		$a_00_1 = {2f 73 70 79 2f 53 79 6e 63 44 6f 6e 65 3f 69 6d 65 69 3d } //2 /spy/SyncDone?imei=
		$a_00_2 = {6d 6f 62 69 6c 65 5f 64 65 76 69 63 65 5f 72 65 61 64 5f 73 6d 73 73 } //1 mobile_device_read_smss
		$a_00_3 = {61 75 74 6f 53 79 6e 63 53 6d 73 73 } //1 autoSyncSmss
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}