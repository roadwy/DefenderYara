
rule MonitoringTool_AndroidOS_Toreoc_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Toreoc.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 32 43 61 6c 6c 52 65 63 5f 64 6f 6e 74 5f 73 68 6f 77 } //1 S2CallRec_dont_show
		$a_00_1 = {46 69 78 20 63 61 6c 6c 20 72 65 63 6f 72 64 69 6e 67 } //1 Fix call recording
		$a_00_2 = {70 68 6f 6e 65 5f 70 69 63 6b 65 72 5f 61 70 70 6c 79 5f 66 6f 72 5f 6f 75 74 67 6f 69 6e 67 } //1 phone_picker_apply_for_outgoing
		$a_00_3 = {52 65 63 6f 72 64 20 73 61 76 65 64 20 74 6f } //1 Record saved to
		$a_00_4 = {50 65 72 73 69 73 74 65 6e 63 65 4d 61 6e 61 67 65 72 } //1 PersistenceManager
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}