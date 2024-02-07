
rule Trojan_MacOS_FishHook_A_MTB{
	meta:
		description = "Trojan:MacOS/FishHook.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {44 65 73 6b 74 6f 70 2f 72 65 76 65 72 73 65 2d 70 72 6f 6a 65 63 74 2f 73 76 6e 2f 43 6f 64 65 2f 4d 61 63 4f 53 58 2f 43 26 4a 20 53 6f 6c 75 74 69 6f 6e 73 } //01 00  Desktop/reverse-project/svn/Code/MacOSX/C&J Solutions
		$a_00_1 = {43 4a 46 69 73 68 50 6f 6f 6c 48 6f 6f 6b 20 73 74 61 72 74 43 61 70 74 75 72 65 } //01 00  CJFishPoolHook startCapture
		$a_00_2 = {43 4a 46 69 73 68 50 6f 6f 6c 48 6f 6f 6b 2e 6d } //01 00  CJFishPoolHook.m
		$a_00_3 = {66 69 73 68 68 6f 6f 6b 2e 63 } //00 00  fishhook.c
	condition:
		any of ($a_*)
 
}