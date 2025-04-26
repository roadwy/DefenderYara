
rule Adware_Win32_Gator_GJ_ibt{
	meta:
		description = "Adware:Win32/Gator.GJ!ibt,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {74 72 69 63 6b 6c 65 2e 67 61 74 6f 72 2e 62 6c 61 } //1 trickle.gator.bla
		$a_01_1 = {51 77 65 72 74 79 75 69 49 6e 66 } //1 QwertyuiInf
		$a_01_2 = {53 69 6c 65 6e 74 53 65 74 75 70 20 63 6f 6d 70 6c 65 74 65 73 } //1 SilentSetup completes
		$a_01_3 = {54 72 69 63 6b 6c 65 72 52 75 6e 6e 69 6e 67 4d 75 74 65 78 } //1 TricklerRunningMutex
		$a_01_4 = {67 61 74 6f 72 2e 63 6f 6d } //1 gator.com
		$a_01_5 = {49 45 47 61 74 6f 72 2e 69 6e 66 } //1 IEGator.inf
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}