
rule Trojan_AndroidOS_SAgent_P_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgent.P!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5f 73 65 6e 64 73 6d 73 5f 63 68 69 6c 64 5f 6c 69 73 74 65 6e 65 72 } //01 00  _sendsms_child_listener
		$a_01_1 = {5f 69 6e 66 6f 64 65 76 69 63 65 } //01 00  _infodevice
		$a_01_2 = {63 6f 6d 2f 6b 61 62 6f 6f 73 2f 76 69 70 } //01 00  com/kaboos/vip
		$a_01_3 = {5f 67 65 74 41 6c 6c 43 6f 6e 74 61 63 74 73 } //01 00  _getAllContacts
		$a_01_4 = {77 77 77 2e 6c 69 6b 65 34 6c 69 6b 65 2e 6f 72 67 } //00 00  www.like4like.org
	condition:
		any of ($a_*)
 
}