
rule HackTool_Win32_Edrblok_YAB_MTB{
	meta:
		description = "HackTool:Win32/Edrblok.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {46 77 70 6d 45 6e 67 69 6e 65 4f 70 65 6e 30 } //1 FwpmEngineOpen0
		$a_01_1 = {45 44 52 20 70 72 6f 63 65 73 73 20 77 61 73 20 64 65 74 65 63 74 65 64 2e 20 50 6c 65 61 73 65 20 64 6f 75 62 6c 65 20 63 68 65 63 6b 20 74 68 65 20 65 64 72 50 72 6f 63 65 73 73 20 6c 69 73 74 20 6f 72 20 61 64 64 20 74 68 65 20 66 69 6c 74 65 72 20 6d 61 6e 75 61 6c 6c 79 20 75 73 69 6e 67 20 27 62 6c 6f 63 6b 27 20 63 6f 6d 6d 61 6e 64 } //1 EDR process was detected. Please double check the edrProcess list or add the filter manually using 'block' command
		$a_01_2 = {55 6e 61 62 6c 65 20 74 6f 20 66 69 6e 64 20 61 6e 79 20 57 46 50 20 66 69 6c 74 65 72 20 63 72 65 61 74 65 64 20 62 79 20 74 68 69 73 20 74 6f 6f 6c } //1 Unable to find any WFP filter created by this tool
		$a_01_3 = {44 65 74 65 63 74 65 64 20 72 75 6e 6e 69 6e 67 20 45 44 52 20 70 72 6f 63 65 73 73 } //1 Detected running EDR process
		$a_01_4 = {41 64 64 65 64 20 57 46 50 20 66 69 6c 74 65 72 20 66 6f 72 20 22 25 53 22 20 28 46 69 6c 74 65 72 20 69 64 3a 20 25 6c 6c 75 2c 20 49 50 76 34 20 6c 61 79 65 72 } //1 Added WFP filter for "%S" (Filter id: %llu, IPv4 layer
		$a_01_5 = {62 6c 6f 63 6b 65 64 72 2f 62 6c 6f 63 6b 2f 75 6e 62 6c 6f 63 6b 61 6c 6c 2f 75 6e 62 6c 6f 63 6b } //1 blockedr/block/unblockall/unblock
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}