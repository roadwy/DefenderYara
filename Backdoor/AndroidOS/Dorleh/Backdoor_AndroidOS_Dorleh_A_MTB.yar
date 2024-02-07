
rule Backdoor_AndroidOS_Dorleh_A_MTB{
	meta:
		description = "Backdoor:AndroidOS/Dorleh.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 53 6d 73 53 69 6d 4d 65 73 73 61 67 65 73 } //01 00  CSmsSimMessages
		$a_01_1 = {43 6f 6e 74 61 63 74 50 68 6f 6e 65 73 } //01 00  ContactPhones
		$a_01_2 = {6c 61 73 74 5f 74 69 6d 65 5f 63 6f 6e 74 61 63 74 65 64 } //01 00  last_time_contacted
		$a_01_3 = {2f 2f 62 72 6f 77 73 65 72 2f 73 65 61 72 63 68 65 73 } //01 00  //browser/searches
		$a_01_4 = {67 65 74 43 6f 6e 6e 65 63 74 69 6f 6e 49 6e 66 6f } //01 00  getConnectionInfo
		$a_00_5 = {4c 65 78 61 6d 70 6c 65 2f 68 65 6c 6c 6f 61 6e 64 72 6f 69 64 2f 65 } //00 00  Lexample/helloandroid/e
	condition:
		any of ($a_*)
 
}