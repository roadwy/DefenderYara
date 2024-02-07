
rule Trojan_AndroidOS_Monocle_C{
	meta:
		description = "Trojan:AndroidOS/Monocle.C,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {75 70 6c 6f 61 64 46 69 6c 65 54 6f 41 67 65 6e 74 43 6d 64 } //01 00  uploadFileToAgentCmd
		$a_00_1 = {41 6e 64 72 6f 69 64 2f 64 61 74 61 2f 73 65 72 76 38 32 30 32 39 36 35 } //01 00  Android/data/serv8202965
		$a_00_2 = {45 56 45 4e 54 5f 41 50 50 5f 43 48 41 4e 47 45 5f 53 54 41 54 45 } //01 00  EVENT_APP_CHANGE_STATE
		$a_00_3 = {46 61 6b 65 57 72 6f 6e 67 43 6d 64 } //00 00  FakeWrongCmd
		$a_00_4 = {5d 04 00 } //00 c8 
	condition:
		any of ($a_*)
 
}