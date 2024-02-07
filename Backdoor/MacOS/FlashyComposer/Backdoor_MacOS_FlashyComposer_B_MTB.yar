
rule Backdoor_MacOS_FlashyComposer_B_MTB{
	meta:
		description = "Backdoor:MacOS/FlashyComposer.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 4c 61 75 6e 63 68 41 67 65 6e 74 73 2f 63 6f 6d 2e 47 65 74 46 6c 61 73 68 50 6c 61 79 65 72 2e 70 6c 69 73 74 } //01 00  /LaunchAgents/com.GetFlashPlayer.plist
		$a_00_1 = {61 6c 65 6b 73 20 70 61 70 61 6e 64 6f 70 75 6c 6f } //01 00  aleks papandopulo
		$a_00_2 = {53 4e 36 45 55 33 36 57 45 39 } //01 00  SN6EU36WE9
		$a_00_3 = {63 6f 6d 2e 70 61 70 61 6e 64 6f 70 75 6c 6f 2e 61 6c 65 78 } //01 00  com.papandopulo.alex
		$a_00_4 = {64 6f 77 6e 6c 6f 61 64 61 72 63 68 69 76 65 73 2e 73 65 72 76 65 68 74 74 70 2e 63 6f 6d } //00 00  downloadarchives.servehttp.com
		$a_00_5 = {5d 04 00 } //00 42 
	condition:
		any of ($a_*)
 
}