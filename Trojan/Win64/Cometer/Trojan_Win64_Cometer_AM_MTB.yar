
rule Trojan_Win64_Cometer_AM_MTB{
	meta:
		description = "Trojan:Win64/Cometer.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 06 00 00 0a 00 "
		
	strings :
		$a_02_0 = {48 89 5c 24 08 48 89 6c 24 18 48 89 74 24 20 57 41 56 41 57 48 81 ec c0 00 00 00 48 8b 05 90 01 01 3c 01 00 48 33 c4 48 89 84 24 b0 00 00 00 48 8d 0d 90 01 01 1f 01 00 4c 8b 90 01 01 ff 15 eb ac 00 00 48 8b c8 48 8d 15 90 01 01 1f 01 00 48 8b d8 ff 15 90 01 01 ac 00 00 48 8d 15 90 01 01 1f 01 00 48 8b cb 48 8b f8 ff 15 90 01 01 ac 00 00 48 8d 15 90 01 01 1f 01 00 48 8b cb 48 8b f0 ff 15 90 01 01 ac 90 00 } //03 00 
		$a_80_1 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //LoadResource  03 00 
		$a_80_2 = {4c 6f 63 6b 52 65 73 6f 75 72 63 65 } //LockResource  03 00 
		$a_80_3 = {52 74 6c 4c 6f 6f 6b 75 70 46 75 6e 63 74 69 6f 6e 45 6e 74 72 79 } //RtlLookupFunctionEntry  03 00 
		$a_80_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //IsDebuggerPresent  03 00 
		$a_80_5 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //IsProcessorFeaturePresent  00 00 
	condition:
		any of ($a_*)
 
}