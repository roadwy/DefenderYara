
rule Trojan_AndroidOS_Locker_A{
	meta:
		description = "Trojan:AndroidOS/Locker.A,SIGNATURE_TYPE_DEXHSTR_EXT,09 00 09 00 07 00 00 "
		
	strings :
		$a_00_0 = {70 72 69 76 65 74 } //2 privet
		$a_00_1 = {69 73 5f 69 6d 75 6e 6e 69 74 79 } //2 is_imunnity
		$a_00_2 = {33 39 33 38 33 38 } //2 393838
		$a_00_3 = {6c 6f 63 6b 65 72 5f 69 6d 6d 75 6e 69 74 79 } //2 locker_immunity
		$a_00_4 = {66 6f 72 63 65 2d 6c 6f 63 6b 65 64 } //1 force-locked
		$a_00_5 = {53 74 61 72 74 20 75 6e 62 6c 6f 63 6b 65 64 20 70 72 6f 63 65 73 73 21 } //1 Start unblocked process!
		$a_00_6 = {73 61 76 65 5f 6d 65 73 73 61 67 65 5f 68 69 73 74 6f 72 79 } //1 save_message_history
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=9
 
}
rule Trojan_AndroidOS_Locker_A_2{
	meta:
		description = "Trojan:AndroidOS/Locker.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 6d 6f 6c 69 2f 6c 6f 63 6b 2f 6c 6f 63 6b } //3 Lcom/moli/lock/lock
		$a_00_1 = {4c 63 6f 6d 2f 6d 6f 6c 69 2f 6c 6f 63 6b 2f 42 6f 6f 74 42 72 6f 61 64 63 61 73 74 52 65 63 65 69 76 65 72 } //1 Lcom/moli/lock/BootBroadcastReceiver
		$a_00_2 = {4c 61 6e 64 72 6f 69 64 2f 76 69 65 77 2f 57 69 6e 64 6f 77 4d 61 6e 61 67 65 72 24 4c 61 79 6f 75 74 50 61 72 61 6d 73 } //1 Landroid/view/WindowManager$LayoutParams
		$a_00_3 = {63 6f 6d 2e 61 69 64 65 2e 72 75 6e 74 69 6d 65 2e 56 49 45 57 5f 4c 4f 47 43 41 54 5f 45 4e 54 52 59 } //1 com.aide.runtime.VIEW_LOGCAT_ENTRY
		$a_00_4 = {61 64 64 56 69 65 77 } //1 addView
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}