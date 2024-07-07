
rule MonitoringTool_AndroidOS_Lypro_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Lypro.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {6c 6f 63 61 74 65 6d 65 5f 70 72 6f 32 2e 49 47 4e 4f 52 45 5f 4d 45 } //1 locateme_pro2.IGNORE_ME
		$a_00_1 = {46 69 6e 64 4d 65 } //1 FindMe
		$a_00_2 = {6c 6f 63 61 74 65 5f 6b 65 79 5f 70 72 6f } //1 locate_key_pro
		$a_00_3 = {4c 6f 63 61 74 65 59 6f 75 72 50 68 6f 6e 65 50 52 4f } //1 LocateYourPhonePRO
		$a_00_4 = {67 65 74 4c 61 73 74 4b 6e 6f 77 6e 4c 6f 63 61 74 69 6f 6e } //1 getLastKnownLocation
		$a_00_5 = {4c 65 73 2f 74 68 65 6d 6f 76 65 2f 6c 6f 63 61 74 65 6d 65 5f 70 72 6f 32 2f 4c 6f 63 61 74 69 6f 6e 53 65 72 76 69 63 65 } //1 Les/themove/locateme_pro2/LocationService
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}