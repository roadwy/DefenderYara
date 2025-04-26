
rule Trojan_AndroidOS_AdLocker_A_MTB{
	meta:
		description = "Trojan:AndroidOS/AdLocker.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 66 6f 72 63 65 6d 65 6c 6c 6f 73 74 75 64 69 6f 2e 62 6c 75 72 77 61 6c 6c 70 61 70 65 72 66 72 65 65 2e 4c 6f 63 6b 53 63 72 65 65 6e 53 65 72 76 69 63 65 } //1 com.forcemellostudio.blurwallpaperfree.LockScreenService
		$a_00_1 = {73 74 61 72 74 54 72 61 63 6b 69 6e 67 41 70 70 73 46 6c 79 65 72 45 76 65 6e 74 } //1 startTrackingAppsFlyerEvent
		$a_00_2 = {73 74 61 72 74 53 65 72 76 65 72 53 74 61 74 73 55 70 64 61 74 65 } //1 startServerStatsUpdate
		$a_00_3 = {61 64 64 41 64 76 65 72 74 69 73 65 72 49 44 44 61 74 61 } //1 addAdvertiserIDData
		$a_00_4 = {67 65 74 50 68 6f 6e 65 43 61 6c 6c 73 43 6f 75 6e 74 } //1 getPhoneCallsCount
		$a_00_5 = {62 72 6f 61 64 63 61 73 74 43 61 72 64 49 6e 66 6f } //1 broadcastCardInfo
		$a_00_6 = {67 65 74 4c 61 73 74 53 4d 53 43 6f 6e 74 61 63 74 } //1 getLastSMSContact
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}