
rule Trojan_AndroidOS_Bankbot_D_MTB{
	meta:
		description = "Trojan:AndroidOS/Bankbot.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 73 61 64 61 73 64 77 71 65 77 71 61 73 2e 64 73 71 77 65 71 77 64 73 } //01 00  com.sadasdwqewqas.dsqweqwds
		$a_00_1 = {75 70 6c 6f 61 64 43 6f 6e 74 61 63 74 73 2e 70 68 70 } //01 00  uploadContacts.php
		$a_00_2 = {67 65 74 49 6e 73 74 61 6c 6c 65 64 41 70 70 6c 69 63 61 74 69 6f 6e 73 } //01 00  getInstalledApplications
		$a_00_3 = {73 74 61 72 74 74 72 61 63 6b 69 6e 67 } //01 00  starttracking
		$a_00_4 = {73 74 6f 70 53 65 6c 66 } //00 00  stopSelf
	condition:
		any of ($a_*)
 
}