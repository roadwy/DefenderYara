
rule Trojan_Win64_IcedID_MO_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {49 8b d5 49 8b ce eb aa 30 41 ff 8b 47 18 eb 00 3b d8 72 0f } //01 00 
		$a_01_1 = {76 63 61 62 } //00 00  vcab
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_MO_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 79 47 31 4f 34 2e 64 6c 6c } //01 00  NyG1O4.dll
		$a_01_1 = {61 77 74 75 67 68 6a 64 61 73 75 } //01 00  awtughjdasu
		$a_01_2 = {43 62 46 52 53 47 44 55 52 70 } //01 00  CbFRSGDURp
		$a_01_3 = {44 51 4d 42 43 78 72 78 67 6d 4b } //01 00  DQMBCxrxgmK
		$a_01_4 = {57 41 4c 76 6d 76 70 } //01 00  WALvmvp
		$a_01_5 = {44 46 6b 48 4c 4d 62 62 } //00 00  DFkHLMbb
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_MO_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.MO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {75 68 61 6e 64 61 68 79 67 73 74 64 67 61 68 75 69 73 6a 64 6a 6e 73 75 61 79 73 } //02 00  uhandahygstdgahuisjdjnsuays
		$a_01_1 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //02 00  WaitForSingleObject
		$a_01_2 = {43 72 65 61 74 65 45 76 65 6e 74 41 } //02 00  CreateEventA
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00  VirtualAlloc
	condition:
		any of ($a_*)
 
}