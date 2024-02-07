
rule Trojan_AndroidOS_Locker_RA_MSR{
	meta:
		description = "Trojan:AndroidOS/Locker.RA!MSR,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {6c 6f 63 6b 2f 4c 6f 63 6b 31 53 65 72 76 69 63 65 } //01 00  lock/Lock1Service
		$a_00_1 = {70 72 6f 74 65 63 74 6f 72 2f 4b 65 65 70 4c 69 76 65 41 63 74 69 76 69 74 79 } //01 00  protector/KeepLiveActivity
		$a_00_2 = {70 72 6f 74 65 63 74 6f 72 2f 41 6c 69 76 65 4a 6f 62 31 53 65 72 76 69 63 65 } //01 00  protector/AliveJob1Service
		$a_00_3 = {2f 70 61 79 6c 6f 61 64 2e 61 70 6b } //00 00  /payload.apk
	condition:
		any of ($a_*)
 
}