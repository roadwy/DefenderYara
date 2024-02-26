
rule Trojan_Win32_CobaltStrike_AC_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 c9 83 f8 0e 0f 45 c8 8a 81 8c 62 08 10 30 04 32 42 8d 41 01 3b d7 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CobaltStrike_AC_MTB_2{
	meta:
		description = "Trojan:Win32/CobaltStrike.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {4d 69 63 72 6f 73 6f 66 74 20 42 61 73 65 20 43 72 79 70 74 6f 67 72 61 70 68 69 63 20 50 72 6f 76 69 64 65 72 20 76 31 2e 30 } //Microsoft Base Cryptographic Provider v1.0  03 00 
		$a_80_1 = {4c 69 62 54 6f 6d 4d 61 74 68 } //LibTomMath  03 00 
		$a_80_2 = {49 6e 74 65 72 6e 65 74 51 75 65 72 79 44 61 74 61 41 76 61 69 6c 61 62 6c 65 } //InternetQueryDataAvailable  03 00 
		$a_80_3 = {48 74 74 70 41 64 64 52 65 71 75 65 73 74 48 65 61 64 65 72 73 41 } //HttpAddRequestHeadersA  03 00 
		$a_80_4 = {62 65 61 63 6f 6e 2e 64 6c 6c } //beacon.dll  03 00 
		$a_80_5 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 40 34 } //ReflectiveLoader@4  03 00 
		$a_80_6 = {72 6f 75 6e 64 2d 74 72 75 74 68 2d 35 38 63 38 } //round-truth-58c8  00 00 
	condition:
		any of ($a_*)
 
}