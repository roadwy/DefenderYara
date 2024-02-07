
rule Backdoor_AndroidOS_SerBG_A_MTB{
	meta:
		description = "Backdoor:AndroidOS/SerBG.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 69 6c 65 67 65 64 53 6d 73 52 65 63 65 69 76 65 72 } //01 00  PrivilegedSmsReceiver
		$a_00_1 = {62 6c 6f 63 6b 20 74 68 65 20 73 6d 73 } //01 00  block the sms
		$a_00_2 = {72 65 70 6c 79 20 74 68 65 20 73 6d 73 20 77 69 74 68 20 6e 75 6d } //01 00  reply the sms with num
		$a_00_3 = {46 61 6b 65 4c 61 6e 75 63 68 65 72 41 63 74 69 76 69 74 79 } //01 00  FakeLanucherActivity
		$a_00_4 = {73 61 76 65 50 68 6f 6e 65 49 6e 66 6f } //01 00  savePhoneInfo
		$a_00_5 = {6f 6e 65 20 72 6f 75 6e 64 20 73 6d 73 20 73 65 6e 64 20 72 65 63 65 69 76 65 72 } //01 00  one round sms send receiver
		$a_00_6 = {73 6d 73 5f 62 6c 6f 63 6b 5f 74 69 6d 65 } //00 00  sms_block_time
		$a_00_7 = {5d 04 00 00 72 } //94 04 
	condition:
		any of ($a_*)
 
}