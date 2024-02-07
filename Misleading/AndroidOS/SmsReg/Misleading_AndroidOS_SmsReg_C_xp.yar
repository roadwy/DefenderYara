
rule Misleading_AndroidOS_SmsReg_C_xp{
	meta:
		description = "Misleading:AndroidOS/SmsReg.C!xp,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {76 72 2e 70 68 70 3f 70 61 79 5f 49 64 3d } //01 00  vr.php?pay_Id=
		$a_00_1 = {2e 77 78 61 70 69 2e 57 58 50 61 79 45 6e 74 72 79 41 63 74 69 76 69 74 79 } //01 00  .wxapi.WXPayEntryActivity
		$a_00_2 = {76 69 73 69 74 6f 72 31 2e 70 68 70 3f 70 61 79 5f 49 64 3d } //01 00  visitor1.php?pay_Id=
		$a_00_3 = {75 6e 72 65 67 69 73 74 65 72 4f 62 73 65 72 76 65 72 } //01 00  unregisterObserver
		$a_00_4 = {74 68 65 20 72 65 6d 6f 74 65 20 70 72 6f 63 65 73 73 20 64 69 65 } //01 00  the remote process die
		$a_00_5 = {70 68 70 36 2e 71 79 6a 75 6a 75 2e 63 6f 6d 2f 6a 73 6f 6e 32 2f 6d 79 2e 70 68 70 3f 70 61 79 5f 49 64 3d } //00 00  php6.qyjuju.com/json2/my.php?pay_Id=
	condition:
		any of ($a_*)
 
}