
rule Trojan_AndroidOS_Donot_C{
	meta:
		description = "Trojan:AndroidOS/Donot.C,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_00_0 = {41 70 70 4b 69 6c 6c 43 68 65 63 6b 53 65 72 76 69 63 65 } //2 AppKillCheckService
		$a_00_1 = {74 62 6c 5f 61 6c 6c 5f 63 6f 6e 74 61 63 74 5f 6c 69 73 74 } //2 tbl_all_contact_list
		$a_00_2 = {74 61 62 6c 65 5f 67 72 6f 75 70 5f 72 6f 73 74 65 72 } //2 table_group_roster
		$a_00_3 = {72 6f 73 74 65 72 5f 6c 69 73 74 5f 6e 65 77 5f 6d 65 73 73 61 67 65 5f 63 6f 75 6e 74 } //2 roster_list_new_message_count
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=6
 
}