
rule HackTool_MacOS_SuspBinary_V{
	meta:
		description = "HackTool:MacOS/SuspBinary.V,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_00_0 = {43 59 4d 5f 50 69 70 65 46 69 6c 65 5f } //1 CYM_PipeFile_
		$a_00_1 = {43 79 6d 75 6c 61 74 65 40 54 4d 52 } //1 Cymulate@TMR
		$a_00_2 = {43 79 6d 75 6c 61 74 65 44 79 6c 69 62 48 69 6a 61 63 6b } //1 CymulateDylibHijack
		$a_00_3 = {3c 43 79 6d 41 72 67 73 3e } //1 <CymArgs>
		$a_00_4 = {43 79 6d 75 6c 61 74 65 45 44 52 53 63 65 6e 61 72 69 6f 45 78 65 63 75 74 6f 72 } //1 CymulateEDRScenarioExecutor
		$a_00_5 = {43 79 6d 75 6c 61 74 65 2f 41 67 65 6e 74 2f 65 64 72 2f } //1 Cymulate/Agent/edr/
		$a_00_6 = {43 59 4d 55 4c 41 54 45 5f 45 44 52 5f 4d 55 54 45 58 } //1 CYMULATE_EDR_MUTEX
		$a_00_7 = {65 64 72 5f 61 74 74 61 63 6b 73 5f 70 61 74 68 } //1 edr_attacks_path
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=5
 
}