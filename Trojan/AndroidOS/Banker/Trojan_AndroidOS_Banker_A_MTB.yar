
rule Trojan_AndroidOS_Banker_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Banker.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 77 6f 6f 72 69 2f 57 6f 6f 72 69 41 63 6f 75 6e 74 49 6e 66 6f } //01 00  com/woori/WooriAcountInfo
		$a_00_1 = {41 63 6f 75 6e 74 50 77 64 41 63 74 69 76 69 74 79 } //01 00  AcountPwdActivity
		$a_00_2 = {63 6f 6d 2f 77 6f 6f 72 69 2f 76 69 65 77 } //00 00  com/woori/view
	condition:
		any of ($a_*)
 
}