
rule Trojan_AndroidOS_TimeThief_A_MTB{
	meta:
		description = "Trojan:AndroidOS/TimeThief.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 61 6c 6c 70 68 6f 6e 65 4e 75 6d 62 65 72 } //1 callphoneNumber
		$a_00_1 = {52 51 53 5f 50 49 43 4b 5f 43 4f 4e 54 41 43 54 } //1 RQS_PICK_CONTACT
		$a_00_2 = {67 65 74 43 6f 6e 74 61 63 74 50 68 6f 6e 65 } //1 getContactPhone
		$a_00_3 = {63 6f 6d 2f 61 6e 64 72 6f 69 64 65 74 68 69 6f 70 69 61 2f 65 74 68 69 6f 74 65 6c 65 63 6f 6d 2f 43 61 6c 6c 4d 65 41 63 74 69 76 69 74 79 } //1 com/androidethiopia/ethiotelecom/CallMeActivity
		$a_00_4 = {61 6c 74 4d 75 6c 74 69 70 6c 65 50 68 6f 6e 65 4e 75 6d 62 65 72 } //1 altMultiplePhoneNumber
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}