
rule TrojanSpy_AndroidOS_SmsThief_AC{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.AC,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {65 78 74 72 61 63 74 4d 65 73 73 61 67 65 73 } //1 extractMessages
		$a_01_1 = {44 61 74 61 52 65 71 75 65 73 74 28 73 65 6e 64 65 72 5f 6e 6f 3d } //1 DataRequest(sender_no=
		$a_00_2 = {67 65 74 6d 6f 62 69 6c 6e 6f } //1 getmobilno
		$a_00_3 = {39 31 31 38 39 31 39 36 37 38 } //1 9118919678
		$a_01_4 = {63 6f 6d 2f 68 65 6c 70 64 65 76 2f 6b 79 63 66 6f 72 6d } //1 com/helpdev/kycform
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}