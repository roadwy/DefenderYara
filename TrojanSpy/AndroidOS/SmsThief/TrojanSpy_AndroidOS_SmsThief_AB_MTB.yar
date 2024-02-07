
rule TrojanSpy_AndroidOS_SmsThief_AB_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.AB!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {72 74 75 69 6f 70 62 68 73 64 61 2e 63 6f 6d } //01 00  rtuiopbhsda.com
		$a_00_1 = {53 4e 53 44 42 42 53 4a 4e 2f 49 53 53 41 53 44 53 } //01 00  SNSDBBSJN/ISSASDS
		$a_00_2 = {6c 6f 61 64 75 72 6c } //01 00  loadurl
		$a_00_3 = {67 65 74 4d 65 73 73 61 67 65 42 6f 64 79 } //01 00  getMessageBody
		$a_00_4 = {63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 73 76 69 2f 52 65 63 65 69 76 65 72 43 6c 61 73 73 } //00 00  com/example/svi/ReceiverClass
	condition:
		any of ($a_*)
 
}