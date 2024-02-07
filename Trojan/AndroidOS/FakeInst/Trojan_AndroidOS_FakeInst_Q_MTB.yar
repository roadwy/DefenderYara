
rule Trojan_AndroidOS_FakeInst_Q_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeInst.Q!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 6b 73 6d 73 6b 65 79 77 6f 72 64 } //01 00  sksmskeyword
		$a_01_1 = {73 63 72 69 70 74 2e 73 74 61 72 70 61 73 73 2e 66 72 2f 73 63 72 69 70 74 2e 70 68 70 3f 69 64 64 3d 35 33 31 35 33 26 61 6d 70 3b 64 61 74 61 73 3d } //01 00  script.starpass.fr/script.php?idd=53153&amp;datas=
		$a_01_2 = {53 6d 73 52 65 63 65 69 76 65 72 } //01 00  SmsReceiver
		$a_01_3 = {64 65 6c 65 74 65 53 4d 53 } //00 00  deleteSMS
	condition:
		any of ($a_*)
 
}