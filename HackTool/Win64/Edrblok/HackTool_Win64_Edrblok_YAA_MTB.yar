
rule HackTool_Win64_Edrblok_YAA_MTB{
	meta:
		description = "HackTool:Win64/Edrblok.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 06 00 00 "
		
	strings :
		$a_01_0 = {46 77 70 6d 45 6e 67 69 6e 65 4f 70 65 6e 30 } //1 FwpmEngineOpen0
		$a_01_1 = {62 6c 6f 63 6b 65 64 72 } //1 blockedr
		$a_01_2 = {75 6e 62 6c 6f 63 6b 61 6c 6c } //1 unblockall
		$a_01_3 = {41 64 64 65 64 20 57 46 50 20 66 69 6c 74 65 72 20 66 6f 72 20 22 25 53 22 20 28 46 69 6c 74 65 72 20 69 64 3a 20 25 64 2c 20 49 50 76 } //2 Added WFP filter for "%S" (Filter id: %d, IPv
		$a_01_4 = {44 65 6c 65 74 65 64 20 63 75 73 74 6f 6d 20 57 46 50 20 70 72 6f 76 69 64 65 72 } //1 Deleted custom WFP provider
		$a_03_5 = {01 10 00 00 c7 45 ?? 87 1e 8e d7 66 c7 45 ?? 44 86 66 c7 45 ?? a5 4e ?? ?? 94 37 d8 09 ec ef c9 71 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_03_5  & 1)*10) >=16
 
}