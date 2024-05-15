
rule Trojan_BAT_RedLineStealer_L_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {44 65 74 65 63 74 45 6d 75 6c 61 74 69 6f 6e } //02 00  DetectEmulation
		$a_01_1 = {53 63 61 6e 41 6e 64 4b 69 6c 6c } //02 00  ScanAndKill
		$a_01_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 52 75 6e 6e 69 6e 67 4f 6e 56 69 72 74 75 61 6c 4d 61 63 68 69 6e 65 } //02 00  ApplicationRunningOnVirtualMachine
		$a_01_3 = {41 70 70 6c 69 63 61 74 69 6f 6e 52 75 6e 6e 69 6e 67 4f 6e 53 61 6e 64 62 6f 78 } //02 00  ApplicationRunningOnSandbox
		$a_01_4 = {48 69 64 65 4f 73 54 68 72 65 61 64 73 } //00 00  HideOsThreads
	condition:
		any of ($a_*)
 
}