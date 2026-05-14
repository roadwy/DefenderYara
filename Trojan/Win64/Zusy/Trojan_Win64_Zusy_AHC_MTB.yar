
rule Trojan_Win64_Zusy_AHC_MTB{
	meta:
		description = "Trojan:Win64/Zusy.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_01_0 = {5b 76 5d 20 41 74 74 65 6d 70 74 69 6e 67 20 54 6f 20 53 74 65 61 6c 20 4f 70 65 6e 65 64 20 46 69 6c 65 20 48 61 6e 64 6c 65 73 2e 2e 2e } //30 [v] Attempting To Steal Opened File Handles...
		$a_01_1 = {46 61 69 6c 65 64 20 54 6f 20 47 65 6e 65 72 61 74 65 20 46 61 6b 65 20 43 6f 6d 6d 61 6e 64 20 4c 69 6e 65 } //10 Failed To Generate Fake Command Line
		$a_01_2 = {5b 76 5d 20 43 61 63 68 69 6e 67 20 25 6c 75 20 42 72 6f 77 73 65 72 20 44 61 74 61 20 46 69 6c 65 73 2e 2e 2e } //20 [v] Caching %lu Browser Data Files...
	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*10+(#a_01_2  & 1)*20) >=60
 
}