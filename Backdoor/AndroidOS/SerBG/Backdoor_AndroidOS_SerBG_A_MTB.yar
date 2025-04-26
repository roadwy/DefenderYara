
rule Backdoor_AndroidOS_SerBG_A_MTB{
	meta:
		description = "Backdoor:AndroidOS/SerBG.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 69 6c 65 67 65 64 53 6d 73 52 65 63 65 69 76 65 72 } //1 PrivilegedSmsReceiver
		$a_00_1 = {62 6c 6f 63 6b 20 74 68 65 20 73 6d 73 } //1 block the sms
		$a_00_2 = {72 65 70 6c 79 20 74 68 65 20 73 6d 73 20 77 69 74 68 20 6e 75 6d } //1 reply the sms with num
		$a_00_3 = {46 61 6b 65 4c 61 6e 75 63 68 65 72 41 63 74 69 76 69 74 79 } //1 FakeLanucherActivity
		$a_00_4 = {73 61 76 65 50 68 6f 6e 65 49 6e 66 6f } //1 savePhoneInfo
		$a_00_5 = {6f 6e 65 20 72 6f 75 6e 64 20 73 6d 73 20 73 65 6e 64 20 72 65 63 65 69 76 65 72 } //1 one round sms send receiver
		$a_00_6 = {73 6d 73 5f 62 6c 6f 63 6b 5f 74 69 6d 65 } //1 sms_block_time
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}