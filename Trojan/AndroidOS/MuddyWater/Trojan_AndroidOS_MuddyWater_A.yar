
rule Trojan_AndroidOS_MuddyWater_A{
	meta:
		description = "Trojan:AndroidOS/MuddyWater.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_00_0 = {63 6c 61 73 73 48 65 6c 70 65 72 2f 46 69 65 6c 64 2f 53 79 73 74 65 6d 49 6e 66 6f 46 69 65 6c 64 3b } //2 classHelper/Field/SystemInfoField;
		$a_00_1 = {44 4f 5f 50 4f 52 54 5f 53 43 41 4e } //1 DO_PORT_SCAN
		$a_00_2 = {49 53 5f 43 4c 49 45 54 4e 54 5f 43 4f 4e 4e 45 43 54 45 44 } //1 IS_CLIETNT_CONNECTED
		$a_00_3 = {72 75 6e 53 70 79 53 65 72 76 69 63 65 } //1 runSpyService
		$a_00_4 = {49 4e 53 54 41 4c 4c 45 44 5f 41 50 50 5f 48 45 41 44 45 52 } //1 INSTALLED_APP_HEADER
		$a_00_5 = {67 65 74 53 6d 61 72 74 43 61 6c 6c 4c 6f 67 } //1 getSmartCallLog
		$a_00_6 = {72 75 6e 5f 73 70 79 5f 73 65 72 76 69 63 65 } //1 run_spy_service
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}