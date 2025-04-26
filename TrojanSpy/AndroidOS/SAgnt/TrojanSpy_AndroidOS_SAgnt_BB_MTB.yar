
rule TrojanSpy_AndroidOS_SAgnt_BB_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.BB!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {52 45 57 44 5f 53 65 6c 65 63 74 } //1 REWD_Select
		$a_01_1 = {43 68 65 63 6b 5f 69 66 5f 69 6e 74 65 72 6e 65 74 5f 73 69 6d 70 6c 65 } //1 Check_if_internet_simple
		$a_01_2 = {53 61 76 65 5f 66 69 72 73 74 5f 72 75 6e } //1 Save_first_run
		$a_01_3 = {43 41 52 44 20 47 4f 54 } //1 CARD GOT
		$a_01_4 = {75 73 65 72 5f 43 72 6e 5f 43 61 72 64 } //1 user_Crn_Card
		$a_01_5 = {50 6f 73 74 44 61 74 61 4e 6f 64 65 43 61 72 64 } //1 PostDataNodeCard
		$a_01_6 = {50 6f 73 74 44 61 74 61 4e 6f 64 65 53 6d 73 } //1 PostDataNodeSms
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}