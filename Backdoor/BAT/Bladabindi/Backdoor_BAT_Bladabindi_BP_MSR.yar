
rule Backdoor_BAT_Bladabindi_BP_MSR{
	meta:
		description = "Backdoor:BAT/Bladabindi.BP!MSR,SIGNATURE_TYPE_PEHSTR,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 53 42 53 70 72 65 61 64 65 72 } //01 00  USBSpreader
		$a_01_1 = {67 65 74 5f 6b 65 79 6c 6f 67 } //01 00  get_keylog
		$a_01_2 = {6b 65 79 6c 6f 67 5f 4b 65 79 50 72 65 73 73 65 64 } //01 00  keylog_KeyPressed
		$a_01_3 = {4d 61 73 74 65 72 41 64 76 61 6e 63 65 64 4b 65 79 6c 6f 67 67 65 72 } //01 00  MasterAdvancedKeylogger
		$a_01_4 = {4b 65 65 65 65 65 79 4c 6f 67 } //00 00  KeeeeeyLog
		$a_01_5 = {00 5d } //04 00  崀
	condition:
		any of ($a_*)
 
}