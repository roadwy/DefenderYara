
rule TrojanSpy_AndroidOS_Inspector_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Inspector.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {74 68 69 73 69 73 6d 65 2e 74 68 69 73 61 70 70 2e 69 6e 73 70 65 63 74 6f 72 } //01 00  thisisme.thisapp.inspector
		$a_00_1 = {73 65 6e 64 41 6c 6c 53 6d 73 } //01 00  sendAllSms
		$a_00_2 = {73 65 6e 64 41 70 70 73 } //01 00  sendApps
		$a_00_3 = {73 65 6e 64 43 61 6c 6c 4c 6f 67 } //01 00  sendCallLog
		$a_00_4 = {73 65 6e 64 43 6f 6e 74 61 63 74 } //00 00  sendContact
		$a_00_5 = {5d 04 00 00 } //69 22 
	condition:
		any of ($a_*)
 
}