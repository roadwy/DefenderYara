
rule Trojan_AndroidOS_Donot_D{
	meta:
		description = "Trojan:AndroidOS/Donot.D,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {53 68 61 72 65 61 62 6c 65 43 6f 6e 74 61 63 74 73 54 65 6d 70 } //02 00  ShareableContactsTemp
		$a_00_1 = {4b 59 4c 4b 30 30 2e 74 78 74 } //02 00  KYLK00.txt
		$a_00_2 = {52 6f 6f 6d 44 62 49 6e 73 5f 49 6d 70 6c } //02 00  RoomDbIns_Impl
		$a_00_3 = {43 68 61 74 4c 69 73 74 44 61 6f 5f 49 6d 70 6c } //00 00  ChatListDao_Impl
	condition:
		any of ($a_*)
 
}