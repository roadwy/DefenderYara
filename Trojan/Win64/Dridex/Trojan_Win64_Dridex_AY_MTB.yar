
rule Trojan_Win64_Dridex_AY_MTB{
	meta:
		description = "Trojan:Win64/Dridex.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {39 4d 4f 59 63 6e 35 4d 64 59 65 53 34 59 45 4d } //9MOYcn5MdYeS4YEM  03 00 
		$a_80_1 = {64 6f 4e 55 4e 79 62 55 4a 59 46 45 43 59 56 53 } //doNUNybUJYFECYVS  03 00 
		$a_80_2 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //IsProcessorFeaturePresent  03 00 
		$a_80_3 = {52 74 6c 4c 6f 6f 6b 75 70 46 75 6e 63 74 69 6f 6e 45 6e 74 72 79 } //RtlLookupFunctionEntry  03 00 
		$a_80_4 = {43 6f 6d 6d 61 6e 64 4c 69 6e 65 54 6f 41 72 67 76 57 } //CommandLineToArgvW  03 00 
		$a_80_5 = {42 6f 78 65 64 41 70 70 53 44 4b 5f 43 72 65 61 74 65 56 69 72 74 75 61 6c 46 69 6c 65 41 } //BoxedAppSDK_CreateVirtualFileA  03 00 
		$a_80_6 = {44 69 73 63 6f 72 64 20 68 65 6c 70 65 72 } //Discord helper  00 00 
	condition:
		any of ($a_*)
 
}