
rule Trojan_Win32_Fragtor_NF_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {74 0d 53 e8 90 01 04 59 85 c0 75 a9 eb 07 e8 90 01 04 89 30 e8 d4 0e 00 00 89 30 8b c7 5f 90 00 } //01 00 
		$a_01_1 = {57 6b 56 32 31 54 53 61 76 } //00 00  WkV21TSav
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fragtor_NF_MTB_2{
	meta:
		description = "Trojan:Win32/Fragtor.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {a1 c8 4f 46 00 6b c9 90 01 01 03 c8 eb 11 8b 55 90 01 01 2b 50 0c 81 fa 00 00 10 00 72 09 83 c0 90 01 01 3b c1 72 eb 33 c0 90 00 } //01 00 
		$a_01_1 = {47 5a 47 4c 58 54 } //00 00  GZGLXT
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fragtor_NF_MTB_3{
	meta:
		description = "Trojan:Win32/Fragtor.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 05 00 "
		
	strings :
		$a_81_0 = {6c 69 62 79 75 67 76 38 36 2e 64 6c 6c } //05 00  libyugv86.dll
		$a_81_1 = {53 6f 66 74 77 61 72 65 5c 70 75 62 6c 75 62 5c 44 75 76 41 70 70 } //02 00  Software\publub\DuvApp
		$a_81_2 = {67 63 72 79 5f 6d 64 5f 73 65 74 6b 65 79 } //02 00  gcry_md_setkey
		$a_81_3 = {54 72 69 61 6c 45 78 70 69 72 65 } //01 00  TrialExpire
		$a_81_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //00 00  VirtualAllocEx
	condition:
		any of ($a_*)
 
}