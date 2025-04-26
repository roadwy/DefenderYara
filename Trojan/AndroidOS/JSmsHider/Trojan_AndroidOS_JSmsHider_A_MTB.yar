
rule Trojan_AndroidOS_JSmsHider_A_MTB{
	meta:
		description = "Trojan:AndroidOS/JSmsHider.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {73 68 6f 77 2e 63 61 6c 6c 6c 6f 67 } //1 show.calllog
		$a_00_1 = {64 69 61 6c 2e 63 61 6c 6c } //1 dial.call
		$a_00_2 = {6c 6f 63 61 74 69 6f 6e 2f 50 68 6f 6e 65 4e 75 6d 62 65 72 51 75 65 72 79 2e 64 61 74 } //1 location/PhoneNumberQuery.dat
		$a_00_3 = {73 6d 73 5f 69 73 72 65 63 65 69 76 65 64 73 6d 73 72 65 63 65 69 76 65 72 } //1 sms_isreceivedsmsreceiver
		$a_00_4 = {6d 43 61 72 64 4e 75 6d 62 65 72 } //1 mCardNumber
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}