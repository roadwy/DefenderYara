
rule Trojan_Win32_Straba_EH_MTB{
	meta:
		description = "Trojan:Win32/Straba.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {89 20 eb 0a a1 90 01 04 83 c0 20 ff d0 8d 05 90 01 04 89 18 89 f0 01 05 90 01 04 89 ea 89 15 90 01 04 01 3d 90 01 04 eb d6 c3 89 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Straba_EH_MTB_2{
	meta:
		description = "Trojan:Win32/Straba.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 00 72 00 65 00 65 00 6e 00 41 00 6d 00 6f 00 76 00 65 00 74 00 68 00 4f 00 75 00 72 00 68 00 65 00 41 00 66 00 6f 00 72 00 6d 00 67 00 72 00 61 00 73 00 73 00 } //01 00  greenAmovethOurheAformgrass
		$a_01_1 = {38 00 4d 00 6f 00 76 00 69 00 6e 00 67 00 63 00 72 00 65 00 65 00 70 00 65 00 74 00 68 00 6d 00 61 00 79 00 45 00 } //01 00  8MovingcreepethmayE
		$a_01_2 = {30 00 74 00 6d 00 61 00 79 00 4b 00 73 00 61 00 79 00 69 00 6e 00 67 00 } //01 00  0tmayKsaying
		$a_01_3 = {6d 00 61 00 6c 00 65 00 74 00 68 00 65 00 69 00 72 00 77 00 65 00 71 00 } //01 00  maletheirweq
		$a_01_4 = {71 00 74 00 72 00 65 00 65 00 47 00 53 00 69 00 77 00 61 00 73 00 } //00 00  qtreeGSiwas
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Straba_EH_MTB_3{
	meta:
		description = "Trojan:Win32/Straba.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 00 66 00 69 00 6c 00 6c 00 63 00 62 00 65 00 68 00 6f 00 6c 00 64 00 45 00 79 00 6f 00 75 00 2e 00 72 00 65 00 69 00 74 00 73 00 65 00 6c 00 66 00 6a 00 } //01 00  FfillcbeholdEyou.reitselfj
		$a_01_1 = {70 00 6c 00 61 00 63 00 65 00 47 00 6d 00 65 00 61 00 74 00 57 00 56 00 54 00 } //01 00  placeGmeatWVT
		$a_01_2 = {67 00 41 00 6c 00 69 00 66 00 65 00 56 00 76 00 66 00 61 00 63 00 65 00 63 00 72 00 65 00 65 00 70 00 69 00 6e 00 67 00 55 00 } //01 00  gAlifeVvfacecreepingU
		$a_01_3 = {71 00 64 00 72 00 79 00 6d 00 65 00 61 00 74 00 67 00 72 00 65 00 65 00 6e 00 6e 00 74 00 73 00 65 00 61 00 73 00 6f 00 6e 00 73 00 } //01 00  qdrymeatgreenntseasons
		$a_01_4 = {4c 00 69 00 67 00 68 00 74 00 62 00 6c 00 65 00 73 00 73 00 65 00 64 00 68 00 69 00 73 00 32 00 62 00 } //00 00  Lightblessedhis2b
	condition:
		any of ($a_*)
 
}