
rule Trojan_Win64_BumbleBee_DD_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 63 c2 44 8b cf 48 8b 93 38 01 00 00 48 33 d0 48 63 c7 48 23 93 e8 02 00 00 48 3b c2 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_BumbleBee_DD_MTB_2{
	meta:
		description = "Trojan:Win64/BumbleBee.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {71 6d 74 32 36 34 74 7a 33 2e 64 6c 6c } //01 00  qmt264tz3.dll
		$a_01_1 = {6f 46 57 6b 52 54 46 77 6a 6d } //01 00  oFWkRTFwjm
		$a_01_2 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //01 00  IsProcessorFeaturePresent
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_01_4 = {43 72 65 61 74 65 4e 61 6d 65 64 50 69 70 65 41 } //01 00  CreateNamedPipeA
		$a_01_5 = {53 77 69 74 63 68 54 6f 46 69 62 65 72 } //00 00  SwitchToFiber
	condition:
		any of ($a_*)
 
}