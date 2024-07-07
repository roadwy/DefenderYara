
rule Trojan_AndroidOS_ADSpy_TA_MTB{
	meta:
		description = "Trojan:AndroidOS/ADSpy.TA!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {68 61 6e 64 6c 65 48 61 63 6b } //1 handleHack
		$a_00_1 = {68 6b 35 39 79 6e 61 64 } //1 hk59ynad
		$a_00_2 = {43 61 6c 6c 4c 6f 67 43 6f 75 6e 74 43 6f 6c 6c 65 63 74 6f 72 } //1 CallLogCountCollector
		$a_00_3 = {44 65 76 69 63 65 49 6e 66 6f 45 78 74 72 61 45 76 61 6c 75 61 74 6f 72 } //1 DeviceInfoExtraEvaluator
		$a_00_4 = {49 6e 73 74 61 6c 6c 61 74 69 6f 6e 54 72 61 63 6b 65 72 } //1 InstallationTracker
		$a_00_5 = {4c 63 6f 6d 2f 63 6c 61 72 65 2f 66 61 63 65 62 6f 6f 6b 70 72 6f 66 69 6c 65 68 61 63 6b 65 72 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //1 Lcom/clare/facebookprofilehacker/MainActivity
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}