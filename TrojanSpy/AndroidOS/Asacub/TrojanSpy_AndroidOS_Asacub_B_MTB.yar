
rule TrojanSpy_AndroidOS_Asacub_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Asacub.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {69 73 41 64 6d 69 6e 41 63 74 69 76 65 } //01 00  isAdminActive
		$a_00_1 = {67 65 74 49 6e 73 74 61 6c 6c 65 64 41 70 70 6c 69 63 61 74 69 6f 6e 73 } //01 00  getInstalledApplications
		$a_03_2 = {0a 00 d8 03 01 ff df 00 90 01 02 8e 00 50 00 02 01 3a 03 90 01 02 d8 00 03 ff 90 00 } //01 00 
		$a_03_3 = {0a 01 df 01 90 01 02 8e 11 50 01 02 03 01 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}