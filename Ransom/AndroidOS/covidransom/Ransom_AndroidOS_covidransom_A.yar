
rule Ransom_AndroidOS_covidransom_A{
	meta:
		description = "Ransom:AndroidOS/covidransom.A,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 65 74 41 70 70 41 73 48 69 64 64 65 6e } //2 setAppAsHidden
		$a_01_1 = {73 68 6f 75 6c 64 52 65 73 74 72 69 63 74 44 65 76 69 63 65 55 73 61 67 65 } //2 shouldRestrictDeviceUsage
		$a_01_2 = {73 74 61 72 74 42 6c 6f 63 6b 65 64 41 63 74 69 76 69 74 79 } //2 startBlockedActivity
		$a_01_3 = {72 65 71 75 65 73 74 42 61 74 74 65 72 79 4f 70 74 69 6d 69 7a 61 74 69 6f 6e } //1 requestBatteryOptimization
		$a_01_4 = {71 75 65 72 79 49 6e 73 74 61 6c 6c 65 64 41 70 70 73 } //1 queryInstalledApps
		$a_01_5 = {73 65 63 72 65 74 50 69 6e } //1 secretPin
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}