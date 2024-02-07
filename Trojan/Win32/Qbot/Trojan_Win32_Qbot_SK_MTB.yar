
rule Trojan_Win32_Qbot_SK_MTB{
	meta:
		description = "Trojan:Win32/Qbot.SK!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 00 66 00 43 00 66 00 71 00 72 00 65 00 6d 00 61 00 79 00 70 00 6f 00 77 00 65 00 72 00 65 00 64 00 37 00 } //01 00  ofCfqremaypowered7
		$a_01_1 = {36 00 63 00 4c 00 69 00 6e 00 75 00 78 00 73 00 6a 00 46 00 72 00 65 00 6e 00 63 00 68 00 5a 00 } //01 00  6cLinuxsjFrenchZ
		$a_01_2 = {6a 65 6e 6e 69 66 65 72 68 69 64 64 65 6e 48 } //01 00  jenniferhiddenH
		$a_01_3 = {79 00 34 00 6f 00 72 00 68 00 61 00 73 00 } //01 00  y4orhas
		$a_01_4 = {73 65 6c 66 2e 65 78 65 } //00 00  self.exe
	condition:
		any of ($a_*)
 
}