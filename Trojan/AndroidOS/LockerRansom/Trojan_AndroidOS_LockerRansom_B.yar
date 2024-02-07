
rule Trojan_AndroidOS_LockerRansom_B{
	meta:
		description = "Trojan:AndroidOS/LockerRansom.B,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 04 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 62 65 6e 64 65 6c 5f 73 6f 66 74 77 61 72 65 2f 61 6e 6c 6f 63 6b 65 72 2f 4c 6f 63 6b 65 72 53 65 72 76 69 63 65 } //01 00  Lcom/bendel_software/anlocker/LockerService
		$a_00_1 = {4c 63 6f 6d 2f 62 65 6e 64 65 6c 5f 73 6f 66 74 77 61 72 65 2f 61 6e 6c 6f 63 6b 65 72 2f 52 65 63 65 69 76 65 72 42 6f 6f 74 43 6f 6d 70 6c 65 74 65 64 } //01 00  Lcom/bendel_software/anlocker/ReceiverBootCompleted
		$a_00_2 = {63 6f 6d 2e 61 64 72 74 2e 4c 4f 47 43 41 54 5f 45 4e 54 52 49 45 53 } //01 00  com.adrt.LOGCAT_ENTRIES
		$a_00_3 = {73 65 74 43 6f 6d 70 6f 6e 65 6e 74 45 6e 61 62 6c 65 64 53 65 74 74 69 6e 67 } //01 00  setComponentEnabledSetting
		$a_00_4 = {4c 61 6e 64 72 6f 69 64 2f 76 69 65 77 2f 57 69 6e 64 6f 77 4d 61 6e 61 67 65 72 24 4c 61 79 6f 75 74 50 61 72 61 6d 73 } //01 00  Landroid/view/WindowManager$LayoutParams
		$a_00_5 = {6c 61 79 6f 75 74 5f 69 6e 66 6c 61 74 65 72 } //00 00  layout_inflater
	condition:
		any of ($a_*)
 
}