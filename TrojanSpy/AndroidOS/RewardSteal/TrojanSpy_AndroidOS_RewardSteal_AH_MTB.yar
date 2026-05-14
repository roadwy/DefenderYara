
rule TrojanSpy_AndroidOS_RewardSteal_AH_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/RewardSteal.AH!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 4d 53 46 6f 72 77 61 72 64 69 6e 67 53 65 72 76 69 63 65 43 68 61 6e 6e 65 6c } //1 SMSForwardingServiceChannel
		$a_01_1 = {2f 64 61 72 6b 34 33 77 65 62 2f 42 6f 6f 74 52 65 63 65 69 76 65 72 } //1 /dark43web/BootReceiver
		$a_01_2 = {44 61 72 6b 34 33 77 65 62 3a 53 4d 53 57 61 6b 65 4c 6f 63 6b } //1 Dark43web:SMSWakeLock
		$a_01_3 = {53 4d 53 46 6f 72 77 61 72 64 69 6e 67 53 65 72 76 69 63 65 } //1 SMSForwardingService
		$a_01_4 = {64 61 72 6b 34 33 77 65 62 2d 53 4d 53 52 65 63 65 69 76 65 72 } //1 dark43web-SMSReceiver
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}