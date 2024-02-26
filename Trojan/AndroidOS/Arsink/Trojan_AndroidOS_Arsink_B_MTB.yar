
rule Trojan_AndroidOS_Arsink_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Arsink.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 65 74 41 6c 6c 43 61 6c 6c 73 48 69 73 74 6f 74 79 } //01 00  getAllCallsHistoty
		$a_01_1 = {5f 67 65 74 41 6c 6c 43 6f 6e 74 61 63 74 73 } //01 00  _getAllContacts
		$a_01_2 = {63 6f 6d 2f 61 69 2f 66 6f 72 6d 61 74 2f 53 70 79 64 72 6f 69 64 41 63 74 69 76 69 74 79 } //01 00  com/ai/format/SpydroidActivity
		$a_01_3 = {5f 68 61 63 6b 5f 73 6d 73 5f 63 68 69 6c 64 5f 6c 69 73 74 65 6e 65 72 } //00 00  _hack_sms_child_listener
	condition:
		any of ($a_*)
 
}