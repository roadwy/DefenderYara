
rule Trojan_AndroidOS_LockerRansom_A_MTB{
	meta:
		description = "Trojan:AndroidOS/LockerRansom.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 74 65 72 6d 75 78 68 61 63 6b 65 72 73 2e 69 64 } //1 com.termuxhackers.id
		$a_00_1 = {6c 6f 67 63 61 74 20 2d 76 20 74 68 72 65 61 64 74 69 6d 65 } //1 logcat -v threadtime
		$a_00_2 = {63 6f 6d 2e 61 64 72 74 2e 4c 4f 47 43 41 54 5f 45 4e 54 52 49 45 53 } //1 com.adrt.LOGCAT_ENTRIES
		$a_00_3 = {4c 61 64 72 74 2f 41 44 52 54 53 65 6e 64 65 72 } //1 Ladrt/ADRTSender
		$a_00_4 = {21 24 44 65 76 61 73 74 61 74 69 6e 67 21 37 78 21 } //1 !$Devastating!7x!
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}