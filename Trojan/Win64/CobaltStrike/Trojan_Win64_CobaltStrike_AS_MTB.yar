
rule Trojan_Win64_CobaltStrike_AS_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 0f af d1 41 01 d2 4d 63 d2 42 8a 04 11 41 30 04 37 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_AS_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 01 c0 31 ca 88 10 48 83 45 ?? 01 90 13 48 8b 45 ?? 48 3b 45 ?? 73 ?? 48 8b 55 ?? 48 8b 45 ?? 48 01 d0 0f b6 08 48 8b 45 ?? ba 00 00 00 00 48 f7 75 ?? 48 8b 45 ?? 48 01 d0 0f b6 10 4c 8b 45 10 48 8b 45 } //1
		$a_03_1 = {48 01 d0 44 89 c2 31 ca 88 10 83 45 ?? 01 83 45 ?? 01 8b 45 ?? 48 98 48 3b 45 ?? 90 13 8b 45 ?? 48 98 48 3b 45 ?? 72 ?? c7 45 ?? 00 00 00 00 8b 45 ?? 48 63 d0 48 8b 45 ?? 48 01 d0 44 0f b6 00 8b 45 ?? 48 63 d0 48 8b 45 ?? 48 01 d0 0f b6 08 8b 45 ?? 48 63 d0 48 8b 45 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_AS_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 "
		
	strings :
		$a_80_0 = {43 46 79 39 32 52 4f 7a 4b 6c 73 5c 72 6f 5c 48 77 74 41 46 2e 70 64 62 } //CFy92ROzKls\ro\HwtAF.pdb  3
		$a_80_1 = {41 70 70 50 6f 6c 69 63 79 47 65 74 50 72 6f 63 65 73 73 54 65 72 6d 69 6e 61 74 69 6f 6e 4d 65 74 68 6f 64 } //AppPolicyGetProcessTerminationMethod  3
		$a_80_2 = {4c 6f 63 61 6c 65 4e 61 6d 65 54 6f 4c 43 49 44 } //LocaleNameToLCID  3
		$a_80_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //IsDebuggerPresent  3
		$a_80_4 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 57 } //GetStartupInfoW  3
		$a_80_5 = {49 6e 69 74 69 61 6c 69 7a 65 43 72 69 74 69 63 61 6c 53 65 63 74 69 6f 6e 41 6e 64 53 70 69 6e 43 6f 75 6e 74 } //InitializeCriticalSectionAndSpinCount  3
		$a_80_6 = {52 74 6c 4c 6f 6f 6b 75 70 46 75 6e 63 74 69 6f 6e 45 6e 74 72 79 } //RtlLookupFunctionEntry  3
		$a_80_7 = {72 38 42 73 48 75 50 65 35 36 6c 5c 69 6c 59 70 5c 69 31 32 74 57 35 53 37 6d 33 } //r8BsHuPe56l\ilYp\i12tW5S7m3  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3) >=24
 
}