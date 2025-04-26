
rule TrojanSpy_AndroidOS_SmsThief_BK_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.BK!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 6d 67 62 2f 73 61 66 65 } //2 com/mgb/safe
		$a_01_1 = {50 68 6f 6e 65 52 65 63 6f 72 64 55 74 69 6c } //1 PhoneRecordUtil
		$a_01_2 = {42 6c 61 63 6b 41 70 70 6c 69 63 61 74 69 6f 6e } //1 BlackApplication
		$a_01_3 = {67 65 74 53 6d 73 49 6e 50 68 6f 6e 65 } //1 getSmsInPhone
		$a_01_4 = {53 6d 73 57 72 69 74 65 4f 70 55 74 69 6c } //1 SmsWriteOpUtil
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}