
rule TrojanSpy_AndroidOS_Fakspy_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Fakspy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 68 61 74 69 6e 66 6f 2e 61 70 6b } //01 00  chatinfo.apk
		$a_00_1 = {49 74 73 20 61 20 53 79 73 74 65 6d 20 41 70 70 6c 69 63 61 74 69 6f 6e 20 0a 20 43 61 6e 27 74 20 75 6e 69 6e 73 74 61 6c 6c } //01 00 
		$a_00_2 = {43 61 6e 27 74 20 54 75 72 6e 20 4f 46 46 20 41 63 63 65 73 73 69 62 69 6c 69 74 79 } //01 00  Can't Turn OFF Accessibility
		$a_00_3 = {2f 61 73 74 72 6f 69 64 53 65 72 76 69 63 65 3b } //01 00  /astroidService;
		$a_00_4 = {4c 6a 69 69 2f 6f 70 74 72 2f 73 65 72 76 69 63 65 2f } //00 00  Ljii/optr/service/
		$a_00_5 = {5d 04 00 } //00 58 
	condition:
		any of ($a_*)
 
}