
rule Trojan_Win64_RootKit_LK_MTB{
	meta:
		description = "Trojan:Win64/RootKit.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 3a 5c 6e 75 6c 6c 6f 75 74 2e 70 64 62 } //01 00  D:\nullout.pdb
		$a_01_1 = {53 61 66 65 6e 67 69 6e 65 20 53 68 69 65 6c 64 65 6e 20 76 32 } //01 00  Safengine Shielden v2
		$a_01_2 = {53 45 53 44 4b 44 75 6d 6d 79 36 34 2e 64 6c 6c } //01 00  SESDKDummy64.dll
		$a_01_3 = {53 45 50 72 6f 74 65 63 74 53 74 61 72 74 4d 75 74 61 74 69 6f 6e } //00 00  SEProtectStartMutation
	condition:
		any of ($a_*)
 
}