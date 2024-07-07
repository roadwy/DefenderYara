
rule TrojanSpy_AndroidOS_SmsThief_A{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {2f 61 70 69 2f 6d 73 67 73 74 6f 72 65 3f 74 61 73 6b 3d } //1 /api/msgstore?task=
		$a_00_1 = {26 74 79 70 65 3d 49 6e 62 6f 78 26 64 61 74 65 66 6f 72 6d 61 74 3d } //1 &type=Inbox&dateformat=
		$a_00_2 = {67 65 74 41 6c 6c 53 6d 73 } //1 getAllSms
		$a_00_3 = {67 65 74 50 65 72 6d } //1 getPerm
		$a_00_4 = {2f 53 6d 73 4c 69 73 74 65 6e 65 72 3b } //1 /SmsListener;
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}