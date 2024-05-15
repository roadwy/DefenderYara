
rule HackTool_Win64_Prolood_A_MTB{
	meta:
		description = "HackTool:Win64/Prolood.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 69 74 68 75 62 2e 63 6f 6d 2f 70 72 65 6c 75 64 65 6f 72 67 2f 6c 69 62 72 61 72 69 65 73 2f 67 6f 2f 74 65 73 74 73 2f 65 6e 64 70 6f 69 6e 74 } //01 00  github.com/preludeorg/libraries/go/tests/endpoint
		$a_01_1 = {45 78 74 72 61 63 74 69 6e 67 20 66 69 6c 65 20 66 6f 72 20 71 75 61 72 61 6e 74 69 6e 65 20 74 65 73 74 } //01 00  Extracting file for quarantine test
		$a_01_2 = {50 61 75 73 69 6e 67 20 66 6f 72 20 33 20 73 65 63 6f 6e 64 73 20 74 6f 20 67 61 75 67 65 20 64 65 66 65 6e 73 69 76 65 } //00 00  Pausing for 3 seconds to gauge defensive
	condition:
		any of ($a_*)
 
}