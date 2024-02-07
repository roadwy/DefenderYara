
rule Adware_Win32_Gator_GJ_ibt{
	meta:
		description = "Adware:Win32/Gator.GJ!ibt,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 72 69 63 6b 6c 65 2e 67 61 74 6f 72 2e 62 6c 61 } //01 00  trickle.gator.bla
		$a_01_1 = {51 77 65 72 74 79 75 69 49 6e 66 } //01 00  QwertyuiInf
		$a_01_2 = {53 69 6c 65 6e 74 53 65 74 75 70 20 63 6f 6d 70 6c 65 74 65 73 } //01 00  SilentSetup completes
		$a_01_3 = {54 72 69 63 6b 6c 65 72 52 75 6e 6e 69 6e 67 4d 75 74 65 78 } //01 00  TricklerRunningMutex
		$a_01_4 = {67 61 74 6f 72 2e 63 6f 6d } //01 00  gator.com
		$a_01_5 = {49 45 47 61 74 6f 72 2e 69 6e 66 } //00 00  IEGator.inf
	condition:
		any of ($a_*)
 
}