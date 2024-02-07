
rule Trojan_Win32_Qakbot_KD_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.KD!MTB,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 65 74 50 6c 75 67 69 6e 49 6e 66 6f 57 } //01 00  petPluginInfoW
		$a_01_1 = {70 70 65 6e 57 } //01 00  ppenW
		$a_01_2 = {70 78 69 74 46 41 52 } //01 00  pxitFAR
		$a_01_3 = {70 65 74 47 6c 6f 62 61 6c 49 6e 66 6f 57 } //01 00  petGlobalInfoW
		$a_01_4 = {70 65 74 4d 69 6e 46 61 72 56 65 72 73 69 6f 6e } //01 00  petMinFarVersion
		$a_01_5 = {70 65 74 4d 69 6e 46 61 72 56 65 72 73 69 6f 6e 57 } //01 00  petMinFarVersionW
		$a_01_6 = {70 65 74 50 6c 75 67 69 6e 49 6e 66 6f } //01 00  petPluginInfo
		$a_01_7 = {70 70 65 6e 50 6c 75 67 69 6e } //01 00  ppenPlugin
		$a_01_8 = {70 70 65 6e 50 6c 75 67 69 6e 57 } //01 00  ppenPluginW
		$a_01_9 = {70 72 6f 63 65 73 73 53 79 6e 63 68 72 6f 45 76 65 6e 74 57 } //01 00  processSynchroEventW
		$a_01_10 = {70 65 74 53 74 61 72 74 75 70 49 6e 66 6f } //01 00  petStartupInfo
		$a_01_11 = {43 6f 6e 45 6d 75 54 68 2e 70 64 62 } //00 00  ConEmuTh.pdb
	condition:
		any of ($a_*)
 
}