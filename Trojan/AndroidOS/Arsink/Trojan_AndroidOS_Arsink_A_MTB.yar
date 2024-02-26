
rule Trojan_AndroidOS_Arsink_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Arsink.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 65 6e 64 4e 75 6d 62 } //01 00  SendNumb
		$a_01_1 = {67 65 74 41 6c 6c 53 6d 73 } //01 00  getAllSms
		$a_01_2 = {5f 67 65 74 41 6c 6c 43 6f 6e 74 61 63 74 73 } //01 00  _getAllContacts
		$a_01_3 = {5f 69 6e 66 6f 64 65 76 69 63 65 } //01 00  _infodevice
		$a_01_4 = {67 65 74 41 6c 6c 43 61 6c 6c 73 48 69 73 74 6f 74 79 } //01 00  getAllCallsHistoty
		$a_01_5 = {6e 69 6b 6f 6c 61 2f 74 65 73 6c 61 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //00 00  nikola/tesla/MainActivity
	condition:
		any of ($a_*)
 
}