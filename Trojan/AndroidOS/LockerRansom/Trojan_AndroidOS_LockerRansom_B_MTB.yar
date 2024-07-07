
rule Trojan_AndroidOS_LockerRansom_B_MTB{
	meta:
		description = "Trojan:AndroidOS/LockerRansom.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 74 65 72 6d 75 78 68 61 63 6b 65 72 73 2f 69 65 2f 4d 79 53 65 72 76 69 63 65 } //1 Lcom/termuxhackers/ie/MyService
		$a_00_1 = {4c 63 6f 6d 2f 74 65 72 6d 75 78 68 61 63 6b 65 72 73 2f 69 65 2f 42 6f 6f 74 52 65 63 65 69 76 65 72 } //1 Lcom/termuxhackers/ie/BootReceiver
		$a_00_2 = {6c 6f 67 63 61 74 20 2d 76 20 74 68 72 65 61 64 74 69 6d 65 } //1 logcat -v threadtime
		$a_00_3 = {63 6f 6d 2e 61 64 72 74 2e 4c 4f 47 43 41 54 5f 45 4e 54 52 49 45 53 } //1 com.adrt.LOGCAT_ENTRIES
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}