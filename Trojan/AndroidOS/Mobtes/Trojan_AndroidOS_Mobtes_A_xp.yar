
rule Trojan_AndroidOS_Mobtes_A_xp{
	meta:
		description = "Trojan:AndroidOS/Mobtes.A!xp,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 6f 66 74 6f 74 65 73 74 40 67 6d 61 69 6c 2e 63 6f 6d } //01 00  softotest@gmail.com
		$a_01_1 = {63 6f 6d 2e 64 72 65 61 6d 73 74 65 70 2e 77 44 72 6f 69 64 4d 6f 76 69 65 } //01 00  com.dreamstep.wDroidMovie
		$a_01_2 = {61 67 69 6c 65 62 69 6e 61 72 79 2f 6d 6f 62 69 6c 65 6d 6f 6e 69 74 6f 72 2f 63 6c 69 65 6e 74 2f } //01 00  agilebinary/mobilemonitor/client/
		$a_01_3 = {43 68 61 6e 67 65 50 61 73 73 77 6f 72 64 41 63 74 69 76 69 74 79 } //01 00  ChangePasswordActivity
		$a_01_4 = {45 76 65 6e 74 4c 69 73 74 41 63 74 69 76 69 74 79 5f 53 4d 53 } //01 00  EventListActivity_SMS
		$a_00_5 = {2f 62 75 79 2e 70 68 70 3f 75 70 67 72 61 64 65 3d 74 72 75 65 26 6b 65 79 3d } //02 00  /buy.php?upgrade=true&key=
		$a_01_6 = {62 69 69 67 65 2e 63 6f 6d } //00 00  biige.com
	condition:
		any of ($a_*)
 
}