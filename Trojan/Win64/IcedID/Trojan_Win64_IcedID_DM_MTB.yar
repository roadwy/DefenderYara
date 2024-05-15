
rule Trojan_Win64_IcedID_DM_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 8a 0c 2a 88 0a 48 ff c2 83 c0 } //01 00 
		$a_03_1 = {41 8b c0 41 ff c0 83 e0 90 01 01 42 8a 44 20 90 01 01 30 01 48 ff c1 44 3b c3 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_DM_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.DM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {50 6c 75 67 69 6e 49 6e 69 74 } //01 00  PluginInit
		$a_01_1 = {65 78 67 44 58 2e 64 6c 6c } //01 00  exgDX.dll
		$a_01_2 = {43 6f 46 69 6c 65 54 69 6d 65 54 6f 44 6f 73 44 61 74 65 54 69 6d 65 } //01 00  CoFileTimeToDosDateTime
		$a_01_3 = {47 65 74 50 6f 6c 79 46 69 6c 6c 4d 6f 64 65 } //01 00  GetPolyFillMode
		$a_01_4 = {43 72 65 61 74 65 50 61 6c 65 74 74 65 } //00 00  CreatePalette
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_DM_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.DM!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {0f b6 45 28 8a 4d 30 33 c8 66 0f 6e c7 88 4d 28 89 5d 20 } //00 00 
	condition:
		any of ($a_*)
 
}