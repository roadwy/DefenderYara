
rule Trojan_Win32_Fragtor_KAH_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.KAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 6f 69 73 75 67 69 66 73 72 75 69 67 41 69 73 67 69 75 68 73 72 67 } //01 00  CoisugifsruigAisgiuhsrg
		$a_01_1 = {49 61 66 75 67 69 6a 61 65 69 67 75 61 65 68 75 67 73 66 64 66 64 73 } //01 00  Iafugijaeiguaehugsfdfds
		$a_01_2 = {56 69 73 69 75 67 66 73 65 75 69 68 41 73 72 67 73 65 69 75 67 73 } //00 00  VisiugfseuihAsrgseiugs
	condition:
		any of ($a_*)
 
}