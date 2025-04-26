
rule TrojanSpy_AndroidOS_SmFrow_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmFrow.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 6d 73 49 6e 66 6f 53 65 72 76 69 63 65 } //1 SmsInfoService
		$a_00_1 = {63 6f 6d 2e 61 6e 64 72 6f 69 64 2e 64 6f 62 62 69 6e 2e 4d 79 53 65 72 76 69 63 65 41 41 } //1 com.android.dobbin.MyServiceAA
		$a_01_2 = {69 73 5f 6c 6f 63 61 74 69 6f 6e 5f 75 70 64 61 74 65 } //1 is_location_update
		$a_01_3 = {69 73 5f 67 65 74 5f 6d 65 73 73 61 67 65 } //1 is_get_message
		$a_01_4 = {69 73 5f 63 6f 6e 74 61 63 74 5f 75 70 64 61 74 65 } //1 is_contact_update
		$a_03_5 = {64 61 6d 69 6e 67 [0-04] 73 6d 73 20 63 6f 6e 74 65 6e 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=5
 
}