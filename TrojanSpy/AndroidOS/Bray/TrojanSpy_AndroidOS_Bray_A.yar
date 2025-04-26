
rule TrojanSpy_AndroidOS_Bray_A{
	meta:
		description = "TrojanSpy:AndroidOS/Bray.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {73 70 5f 64 65 76 69 63 65 5f 75 6e 69 71 75 65 5f 69 64 } //2 sp_device_unique_id
		$a_00_1 = {73 74 61 72 74 53 65 6e 64 4c 6f 63 61 6c } //1 startSendLocal
		$a_00_2 = {73 70 5f 63 6f 6e 6e 65 63 74 5f 75 72 6c } //1 sp_connect_url
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}