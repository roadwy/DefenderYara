
rule Trojan_Win64_Midie_SXG_MTB{
	meta:
		description = "Trojan:Win64/Midie.SXG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 03 00 00 "
		
	strings :
		$a_01_0 = {5b 69 5d 20 46 6f 75 6e 64 20 25 6c 75 20 52 75 6e 6e 69 6e 67 20 42 72 6f 77 73 65 72 20 50 72 6f 63 65 73 73 65 73 } //10 [i] Found %lu Running Browser Processes
		$a_01_1 = {5b 76 5d 20 41 74 74 65 6d 70 74 69 6e 67 20 54 6f 20 53 74 65 61 6c 20 4f 70 65 6e 65 64 20 46 69 6c 65 20 48 61 6e 64 6c 65 73 2e 2e 2e } //30 [v] Attempting To Steal Opened File Handles...
		$a_01_2 = {5b 76 5d 20 53 75 63 63 65 73 73 66 75 6c 6c 79 20 43 6f 70 69 65 64 20 46 69 6c 65 20 56 69 61 20 44 75 70 6c 69 63 61 74 65 64 20 48 61 6e 64 6c 65 } //10 [v] Successfully Copied File Via Duplicated Handle
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*30+(#a_01_2  & 1)*10) >=50
 
}