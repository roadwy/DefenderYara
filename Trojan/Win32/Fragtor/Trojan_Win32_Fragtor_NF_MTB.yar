
rule Trojan_Win32_Fragtor_NF_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 0d 53 e8 ?? ?? ?? ?? 59 85 c0 75 a9 eb 07 e8 ?? ?? ?? ?? 89 30 e8 d4 0e 00 00 89 30 8b c7 5f } //5
		$a_01_1 = {57 6b 56 32 31 54 53 61 76 } //1 WkV21TSav
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_Win32_Fragtor_NF_MTB_2{
	meta:
		description = "Trojan:Win32/Fragtor.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {a1 c8 4f 46 00 6b c9 ?? 03 c8 eb 11 8b 55 ?? 2b 50 0c 81 fa 00 00 10 00 72 09 83 c0 ?? 3b c1 72 eb 33 c0 } //5
		$a_01_1 = {47 5a 47 4c 58 54 } //1 GZGLXT
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_Win32_Fragtor_NF_MTB_3{
	meta:
		description = "Trojan:Win32/Fragtor.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_81_0 = {6c 69 62 79 75 67 76 38 36 2e 64 6c 6c } //5 libyugv86.dll
		$a_81_1 = {53 6f 66 74 77 61 72 65 5c 70 75 62 6c 75 62 5c 44 75 76 41 70 70 } //5 Software\publub\DuvApp
		$a_81_2 = {67 63 72 79 5f 6d 64 5f 73 65 74 6b 65 79 } //2 gcry_md_setkey
		$a_81_3 = {54 72 69 61 6c 45 78 70 69 72 65 } //2 TrialExpire
		$a_81_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 VirtualAllocEx
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*5+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*1) >=15
 
}