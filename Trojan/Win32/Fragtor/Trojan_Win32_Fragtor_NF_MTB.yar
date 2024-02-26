
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