
rule Trojan_AndroidOS_MMrat_A_MTB{
	meta:
		description = "Trojan:AndroidOS/MMrat.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 6d 6d 2f 75 73 65 72 2f 75 69 2f 61 63 74 69 76 69 74 79 } //01 00  Lcom/mm/user/ui/activity
		$a_00_1 = {75 70 6c 6f 61 64 4c 6f 63 6b 53 63 72 65 65 6e 50 61 73 73 77 6f 72 64 } //01 00  uploadLockScreenPassword
		$a_00_2 = {63 61 6e 63 65 6c 4e 6f 74 69 63 65 53 65 72 76 69 63 65 } //00 00  cancelNoticeService
	condition:
		any of ($a_*)
 
}