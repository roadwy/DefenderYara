
rule HackTool_BAT_FrostyStash_C_dha{
	meta:
		description = "HackTool:BAT/FrostyStash.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {5f 75 6e 69 71 49 64 53 79 73 } //1 _uniqIdSys
		$a_01_1 = {5f 75 6e 69 71 49 64 43 6f 72 } //1 _uniqIdCor
		$a_01_2 = {50 72 6f 63 65 73 73 44 61 74 61 } //1 ProcessData
		$a_01_3 = {5f 70 61 74 68 4c 6f 67 } //1 _pathLog
		$a_01_4 = {67 65 74 5f 4d 73 67 } //1 get_Msg
		$a_01_5 = {4a 61 76 61 53 63 72 69 70 74 53 65 72 69 61 6c 69 7a 65 72 } //1 JavaScriptSerializer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}