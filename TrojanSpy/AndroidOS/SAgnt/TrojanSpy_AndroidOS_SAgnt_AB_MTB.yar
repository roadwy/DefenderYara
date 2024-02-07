
rule TrojanSpy_AndroidOS_SAgnt_AB_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.AB!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 6e 64 65 78 79 2e 6f 72 67 2f 77 73 2f 77 73 2e 70 68 70 3f } //01 00  indexy.org/ws/ws.php?
		$a_01_1 = {67 65 74 43 6f 6e 74 61 63 74 4c 69 73 74 } //01 00  getContactList
		$a_01_2 = {63 6f 6d 2e 69 6e 64 65 78 6d 61 73 72 } //01 00  com.indexmasr
		$a_01_3 = {6d 69 6e 69 5f 6e 75 6d 62 65 72 5f 73 65 61 72 63 68 } //01 00  mini_number_search
		$a_01_4 = {6f 6e 49 6e 63 6f 6d 69 6e 67 43 61 6c 6c 41 6e 73 77 65 72 65 64 } //01 00  onIncomingCallAnswered
		$a_01_5 = {6f 6e 4f 75 74 67 6f 69 6e 67 43 61 6c 6c 53 74 61 72 74 65 64 } //00 00  onOutgoingCallStarted
	condition:
		any of ($a_*)
 
}