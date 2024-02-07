
rule Trojan_AndroidOS_SAgnt_J_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.J!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 66 64 65 2f 67 73 41 63 74 69 76 69 74 79 } //01 00  com/fde/gsActivity
		$a_01_1 = {64 66 43 61 6e 63 65 6c 4e 6f 74 69 63 65 53 65 72 76 69 63 65 } //01 00  dfCancelNoticeService
		$a_01_2 = {63 6f 6d 2f 61 73 2f 64 66 43 61 6e 63 65 6c 4e 6f 74 69 63 65 53 65 72 76 69 63 65 } //01 00  com/as/dfCancelNoticeService
		$a_01_3 = {73 67 4d 61 69 6e 53 65 72 76 69 63 65 } //01 00  sgMainService
		$a_01_4 = {79 74 4d 79 52 65 63 65 69 76 65 72 } //00 00  ytMyReceiver
	condition:
		any of ($a_*)
 
}