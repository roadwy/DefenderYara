
rule HackTool_AndroidOS_Mesploit_C{
	meta:
		description = "HackTool:AndroidOS/Mesploit.C,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {74 63 70 3a 2f 2f 38 37 2e 31 39 2e 37 33 2e 38 3a 32 34 30 37 39 } //1 tcp://87.19.73.8:24079
		$a_03_1 = {2e 64 65 78 00 0e 2e [0-20] 00 04 2e 6a 61 72 00 } //1
		$a_01_2 = {63 72 65 61 74 65 4e 65 77 46 69 6c 65 } //1 createNewFile
		$a_01_3 = {44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //1 DexClassLoader
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}