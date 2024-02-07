
rule TrojanSpy_AndroidOS_Fakecall_I_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Fakecall.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 77 69 73 68 2f 64 65 66 61 75 6c 74 63 61 6c 6c 73 65 72 76 69 63 65 2f 61 63 74 69 76 69 74 79 } //01 00  com/wish/defaultcallservice/activity
		$a_00_1 = {67 65 74 5f 6c 69 6d 69 74 5f 70 68 6f 6e 65 5f 6e 75 6d 62 65 72 } //01 00  get_limit_phone_number
		$a_00_2 = {2f 75 73 65 72 2f 75 70 6c 6f 61 64 5f 69 6d 61 67 65 73 } //01 00  /user/upload_images
		$a_00_3 = {2f 75 73 65 72 2f 75 70 6c 6f 61 64 5f 72 65 63 6f 72 64 69 6e 67 5f 66 69 6c 65 } //01 00  /user/upload_recording_file
		$a_00_4 = {2f 75 73 65 72 2f 75 70 6c 6f 61 64 5f 69 6e 66 6f 5f 66 69 6c 65 } //00 00  /user/upload_info_file
	condition:
		any of ($a_*)
 
}