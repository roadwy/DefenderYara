
rule TrojanSpy_AndroidOS_Banker_AJ_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.AJ!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {6c 6f 61 64 5f 73 6d 73 5f 6d 61 73 73 2e 70 68 70 } //1 load_sms_mass.php
		$a_00_1 = {75 70 6c 6f 61 64 5f 73 6d 73 } //1 upload_sms
		$a_00_2 = {72 6f 6f 74 5f 70 68 6f 6e 65 } //1 root_phone
		$a_00_3 = {73 65 74 5f 63 61 72 64 2e 70 68 70 } //1 set_card.php
		$a_00_4 = {62 61 6e 6b 77 65 73 74 2e 6d 6f 62 69 6c 65 } //1 bankwest.mobile
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}