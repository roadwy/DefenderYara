
rule Trojan_BAT_AgentTesla_NEAG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {77 73 68 73 6f 66 74 41 69 6d 6f 6e } //2 wshsoftAimon
		$a_01_1 = {43 4e 42 42 69 6e 76 6f 6b 65 72 31 70 72 6f 78 79 73 74 75 62 } //2 CNBBinvoker1proxystub
		$a_01_2 = {45 58 50 65 72 6f 67 6e 69 } //2 EXPerogni
		$a_01_3 = {77 6d 63 6f 74 61 74 69 6f 6e 42 75 69 6c 64 54 61 73 6b 73 30 6e 69 } //2 wmcotationBuildTasks0ni
		$a_01_4 = {6e 74 69 6f 34 74 52 4d 65 64 73 61 65 78 74 } //2 ntio4tRMedsaext
		$a_01_5 = {43 6f 6d 53 76 63 43 6f 69 62 65 72 73 31 6c 31 6f 31 30 30 } //2 ComSvcCoibers1l1o100
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}