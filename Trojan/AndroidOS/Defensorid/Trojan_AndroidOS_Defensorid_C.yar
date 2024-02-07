
rule Trojan_AndroidOS_Defensorid_C{
	meta:
		description = "Trojan:AndroidOS/Defensorid.C,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 62 72 61 7a 69 6c 2f 61 6e 64 72 6f 69 64 2f 66 72 65 65 2f 43 6f 6d 6d 61 6e 64 53 65 72 76 69 63 65 } //01 00  Lcom/brazil/android/free/CommandService
		$a_01_1 = {43 68 65 63 6b 5f 6f 76 65 72 5f 70 65 72 6d 69 73 73 69 6f 6e } //01 00  Check_over_permission
		$a_00_2 = {6e 65 77 5f 73 63 72 65 65 6e 5f 61 73 6b } //01 00  new_screen_ask
		$a_01_3 = {45 78 70 6f 72 74 5f 49 6e 66 6f 5f 44 65 76 } //01 00  Export_Info_Dev
		$a_01_4 = {41 63 63 65 73 73 45 6e 61 62 6c 65 5f 43 68 65 63 6b } //00 00  AccessEnable_Check
	condition:
		any of ($a_*)
 
}