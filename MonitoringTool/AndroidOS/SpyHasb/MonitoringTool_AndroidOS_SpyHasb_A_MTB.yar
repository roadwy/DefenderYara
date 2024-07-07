
rule MonitoringTool_AndroidOS_SpyHasb_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/SpyHasb.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {4b 69 64 73 4c 6f 63 61 74 6f 72 31 } //1 KidsLocator1
		$a_00_1 = {53 70 79 4d 79 48 75 73 62 61 6e 64 31 } //1 SpyMyHusband1
		$a_01_2 = {53 4d 53 20 4c 6f 67 61 53 4d 53 } //1 SMS LogaSMS
		$a_00_3 = {6b 69 64 73 74 72 61 63 6b 65 72 2e 74 78 74 } //1 kidstracker.txt
		$a_00_4 = {50 68 6f 6e 65 4c 6f 63 61 74 6f 72 56 69 65 77 65 72 } //1 PhoneLocatorViewer
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}