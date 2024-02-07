
rule Trojan_AndroidOS_Joker_D{
	meta:
		description = "Trojan:AndroidOS/Joker.D,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 53 47 5f 54 41 53 4b 5f 50 52 4f 47 52 45 53 53 } //01 00  MSG_TASK_PROGRESS
		$a_01_1 = {4d 53 47 5f 54 41 53 4b 5f 4d 45 52 47 45 5f 46 49 4c 45 3a } //01 00  MSG_TASK_MERGE_FILE:
		$a_00_2 = {6d 43 68 69 6c 64 53 75 63 63 65 73 73 54 69 6d 65 73 3a } //01 00  mChildSuccessTimes:
		$a_01_3 = {2d 2d 4d 53 47 5f 44 4f 4e 57 4c 4f 41 44 } //00 00  --MSG_DONWLOAD
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}