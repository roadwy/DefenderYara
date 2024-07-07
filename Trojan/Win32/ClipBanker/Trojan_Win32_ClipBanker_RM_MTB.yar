
rule Trojan_Win32_ClipBanker_RM_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 c1 c4 7e 00 00 8b 55 90 01 01 8b 02 2b c1 8b 4d 90 01 01 89 01 8b 15 90 01 04 a1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_ClipBanker_RM_MTB_2{
	meta:
		description = "Trojan:Win32/ClipBanker.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 f3 c4 eb f8 1c 8a 0c 01 89 5c 24 90 01 01 88 0c 02 69 54 24 90 01 01 27 e2 d0 4b 89 54 24 90 01 01 83 c0 01 8b 54 24 90 01 01 39 d0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_ClipBanker_RM_MTB_3{
	meta:
		description = "Trojan:Win32/ClipBanker.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 f6 b1 81 29 75 8b 4c 24 90 01 01 89 4c 24 90 01 01 39 f0 75 90 01 01 66 b8 50 d4 66 8b 4c 24 90 01 01 8b 54 24 90 01 01 89 54 24 90 01 01 66 39 c8 76 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_ClipBanker_RM_MTB_4{
	meta:
		description = "Trojan:Win32/ClipBanker.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 5d fc c7 05 90 01 04 00 00 00 00 01 1d 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 5b 8b e5 5d 90 00 } //1
		$a_03_1 = {81 c1 c4 7e 00 00 8b 55 90 01 01 8b 02 2b c1 8b 4d 90 01 01 89 01 8b 15 90 01 04 a1 90 01 04 8d 4c 10 90 01 01 89 0d 90 01 04 8b 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}