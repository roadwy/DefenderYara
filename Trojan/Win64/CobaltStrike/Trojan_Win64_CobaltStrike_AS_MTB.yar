
rule Trojan_Win64_CobaltStrike_AS_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 0f af d1 41 01 d2 4d 63 d2 42 8a 04 11 41 30 04 37 e9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_AS_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 03 00 "
		
	strings :
		$a_80_0 = {43 46 79 39 32 52 4f 7a 4b 6c 73 5c 72 6f 5c 48 77 74 41 46 2e 70 64 62 } //CFy92ROzKls\ro\HwtAF.pdb  03 00 
		$a_80_1 = {41 70 70 50 6f 6c 69 63 79 47 65 74 50 72 6f 63 65 73 73 54 65 72 6d 69 6e 61 74 69 6f 6e 4d 65 74 68 6f 64 } //AppPolicyGetProcessTerminationMethod  03 00 
		$a_80_2 = {4c 6f 63 61 6c 65 4e 61 6d 65 54 6f 4c 43 49 44 } //LocaleNameToLCID  03 00 
		$a_80_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //IsDebuggerPresent  03 00 
		$a_80_4 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 57 } //GetStartupInfoW  03 00 
		$a_80_5 = {49 6e 69 74 69 61 6c 69 7a 65 43 72 69 74 69 63 61 6c 53 65 63 74 69 6f 6e 41 6e 64 53 70 69 6e 43 6f 75 6e 74 } //InitializeCriticalSectionAndSpinCount  03 00 
		$a_80_6 = {52 74 6c 4c 6f 6f 6b 75 70 46 75 6e 63 74 69 6f 6e 45 6e 74 72 79 } //RtlLookupFunctionEntry  03 00 
		$a_80_7 = {72 38 42 73 48 75 50 65 35 36 6c 5c 69 6c 59 70 5c 69 31 32 74 57 35 53 37 6d 33 } //r8BsHuPe56l\ilYp\i12tW5S7m3  00 00 
	condition:
		any of ($a_*)
 
}