
rule Trojan_AndroidOS_FakeApp_Q_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeApp.Q!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 70 65 65 64 5f 68 61 63 6b 73 6d 73 } //01 00  speed_hacksms
		$a_01_1 = {5f 67 65 74 41 6c 6c 43 6f 6e 74 61 63 74 73 } //01 00  _getAllContacts
		$a_01_2 = {41 72 61 62 57 61 72 65 53 4d 53 } //01 00  ArabWareSMS
		$a_01_3 = {63 6f 6d 2f 49 56 41 52 2f 53 50 45 45 44 } //00 00  com/IVAR/SPEED
	condition:
		any of ($a_*)
 
}