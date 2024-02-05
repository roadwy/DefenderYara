
rule Trojan_Win64_IcedID_DC_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {50 6c 75 67 69 6e 49 6e 69 74 } //01 00 
		$a_01_1 = {69 4c 71 56 6b 2e 64 6c 6c } //01 00 
		$a_01_2 = {41 78 30 4b 52 46 33 47 30 68 } //01 00 
		$a_01_3 = {43 67 4e 4d 5a 68 59 41 45 6c 64 } //01 00 
		$a_01_4 = {4a 4f 47 30 64 78 36 74 77 55 } //01 00 
		$a_01_5 = {4b 54 4d 42 74 67 6c 32 62 45 41 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_DC_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {69 48 28 fd 43 03 00 81 c1 c3 9e 26 00 89 48 28 c1 e9 10 81 e1 ff 7f 00 00 8b c1 48 83 c4 28 c3 } //0a 00 
		$a_00_1 = {48 8d 54 24 41 0f 28 05 bc 81 05 00 0f 29 42 ff c7 42 0f ff e7 e1 f7 c6 42 13 00 b8 01 } //03 00 
		$a_80_2 = {52 74 6c 4c 6f 6f 6b 75 70 46 75 6e 63 74 69 6f 6e 45 6e 74 72 79 } //RtlLookupFunctionEntry  03 00 
		$a_80_3 = {54 72 61 6e 73 6c 61 74 65 41 63 63 65 6c 65 72 61 74 6f 72 57 } //TranslateAcceleratorW  00 00 
	condition:
		any of ($a_*)
 
}