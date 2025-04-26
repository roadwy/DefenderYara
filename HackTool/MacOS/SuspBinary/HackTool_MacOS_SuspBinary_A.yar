
rule HackTool_MacOS_SuspBinary_A{
	meta:
		description = "HackTool:MacOS/SuspBinary.A,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {6d 61 6c 69 63 69 6f 75 73 5f 64 79 6c 69 62 } //1 malicious_dylib
		$a_00_1 = {63 6f 6d 2e 61 70 70 6c 65 2e 54 43 43 2f 54 43 43 2e 64 62 } //1 com.apple.TCC/TCC.db
		$a_00_2 = {6f 74 6f 6f 6c 20 2d 6c 20 25 73 20 7c 20 67 72 65 70 20 4c 43 5f 4c 4f 41 44 5f 57 45 41 4b 5f 44 59 4c 49 42 } //1 otool -l %s | grep LC_LOAD_WEAK_DYLIB
		$a_00_3 = {43 79 6d 75 6c 61 74 65 45 44 52 53 63 65 6e 61 72 69 6f 45 78 65 63 75 74 6f 72 } //1 CymulateEDRScenarioExecutor
		$a_00_4 = {63 6f 6d 2e 61 70 70 6c 65 2e 73 65 63 75 72 69 74 79 2e 63 73 2e 64 69 73 61 62 6c 65 2d 6c 69 62 72 61 72 79 2d 76 61 6c 69 64 61 74 69 6f 6e } //1 com.apple.security.cs.disable-library-validation
		$a_00_5 = {65 64 72 5f 61 74 74 61 63 6b 73 5f 70 61 74 68 } //1 edr_attacks_path
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}