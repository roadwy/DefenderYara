
rule VirTool_Win64_Bofprocinj_A{
	meta:
		description = "VirTool:Win64/Bofprocinj.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {69 6d 70 5f 42 65 61 63 6f 6e 44 61 74 61 50 61 72 73 65 } //1 imp_BeaconDataParse
		$a_01_1 = {69 6d 70 5f 42 65 61 63 6f 6e 44 61 74 61 45 78 74 72 61 63 74 } //1 imp_BeaconDataExtract
		$a_03_2 = {42 65 61 63 6f 6e 49 6e 6a 65 63 74 [0-10] 50 72 6f 63 65 73 73 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}