
rule Trojan_AndroidOS_FakePlayer_A_MTB{
	meta:
		description = "Trojan:AndroidOS/FakePlayer.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 70 70 5f 71 75 65 75 65 5f 6d 65 73 73 61 67 65 5f 6c 69 73 74 } //01 00  app_queue_message_list
		$a_01_1 = {64 77 61 70 2e 64 62 } //01 00  dwap.db
		$a_01_2 = {73 65 6e 64 51 75 65 75 65 53 4d 53 } //01 00  sendQueueSMS
		$a_01_3 = {61 70 70 5f 71 75 65 75 65 5f 69 6e 64 65 78 } //00 00  app_queue_index
	condition:
		any of ($a_*)
 
}