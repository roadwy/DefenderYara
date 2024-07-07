
rule MonitoringTool_AndroidOS_Senrec_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Senrec.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {73 61 76 65 49 73 52 65 63 6f 72 64 69 6e 67 } //1 saveIsRecording
		$a_00_1 = {63 6f 6d 2e 68 61 62 72 61 2e 65 78 61 6d 70 6c 65 2e 63 61 6c 6c 5f 72 65 63 6f 72 64 65 72 } //1 com.habra.example.call_recorder
		$a_00_2 = {2f 43 41 4c 4c 5f 52 45 43 4f 52 44 53 } //1 /CALL_RECORDS
		$a_00_3 = {64 69 72 65 63 74 4f 66 43 61 6c 6c } //1 directOfCall
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}