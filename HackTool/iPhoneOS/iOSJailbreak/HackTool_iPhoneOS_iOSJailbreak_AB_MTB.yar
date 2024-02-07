
rule HackTool_iPhoneOS_iOSJailbreak_AB_MTB{
	meta:
		description = "HackTool:iPhoneOS/iOSJailbreak.AB!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {72 75 6e 4a 61 69 6c 62 72 65 61 6b 64 2e 6a 73 } //01 00  runJailbreakd.js
		$a_00_1 = {6c 61 75 6e 63 68 4b 65 72 6e 65 6c 45 78 70 6c 6f 69 74 2e 6a 73 } //01 00  launchKernelExploit.js
		$a_00_2 = {2f 4c 69 6e 75 73 48 65 6e 7a 65 2f 46 75 67 75 31 34 2f 62 6c 6f 62 } //01 00  /LinusHenze/Fugu14/blob
		$a_00_3 = {4a 61 69 6c 62 72 65 61 6b 55 74 69 6c 73 2f 4d 61 63 68 4f 46 69 6c 65 74 79 70 65 2e 73 77 69 66 74 } //01 00  JailbreakUtils/MachOFiletype.swift
		$a_00_4 = {43 6c 6f 73 75 72 65 49 6e 6a 65 63 74 69 6f 6e } //01 00  ClosureInjection
		$a_00_5 = {46 75 67 75 41 70 70 } //00 00  FuguApp
	condition:
		any of ($a_*)
 
}