
rule Backdoor_BAT_Bladabindi_AY{
	meta:
		description = "Backdoor:BAT/Bladabindi.AY,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 09 00 00 0a 00 "
		
	strings :
		$a_01_0 = {00 44 4c 56 00 6e 00 47 54 56 00 53 54 56 00 } //0a 00 
		$a_01_1 = {00 45 4e 42 00 73 00 44 45 42 00 } //01 00 
		$a_01_2 = {41 6e 74 69 41 76 69 72 61 } //01 00  AntiAvira
		$a_01_3 = {55 70 64 61 74 65 53 65 72 76 65 72 42 79 44 6f 77 6e 6c 6f 61 64 } //01 00  UpdateServerByDownload
		$a_01_4 = {43 68 65 63 6b 49 66 4b 69 6c 6c 53 6f 6d 65 50 72 6f 63 65 73 73 65 73 } //01 00  CheckIfKillSomeProcesses
		$a_01_5 = {41 6e 74 69 56 69 72 74 75 61 6c 55 73 69 6e 67 57 4d 49 } //01 00  AntiVirtualUsingWMI
		$a_01_6 = {41 56 47 53 75 73 70 65 6e 64 } //01 00  AVGSuspend
		$a_01_7 = {42 6c 6f 63 6b 53 69 74 65 5f 49 45 5f 46 46 5f 43 68 72 6f 6d 65 } //01 00  BlockSite_IE_FF_Chrome
		$a_01_8 = {00 6b 6c 00 6c 6f 67 } //00 00 
		$a_00_9 = {5d 04 00 00 0f 22 03 80 5c 22 00 00 10 } //22 03 
	condition:
		any of ($a_*)
 
}