
rule Trojan_Win32_RanumBot_KMG_MTB{
	meta:
		description = "Trojan:Win32/RanumBot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {d3 e2 89 5c 24 90 01 01 89 54 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 44 24 90 01 02 44 24 10 a1 90 01 04 3d 1a 0c 00 00 75 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}
rule Trojan_Win32_RanumBot_KMG_MTB_2{
	meta:
		description = "Trojan:Win32/RanumBot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {d3 e2 89 5c 24 90 01 01 89 54 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 44 24 90 01 02 44 24 10 a1 90 01 04 3d 4a 04 00 00 75 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}
rule Trojan_Win32_RanumBot_KMG_MTB_3{
	meta:
		description = "Trojan:Win32/RanumBot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 45 90 01 01 8b 45 90 01 02 45 90 01 01 8b 45 90 01 02 f8 8b 45 90 01 02 c3 33 f8 81 3d 90 01 04 f5 03 00 00 c7 05 90 01 04 36 06 ea e9 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_RanumBot_KMG_MTB_4{
	meta:
		description = "Trojan:Win32/RanumBot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {d3 e2 89 7c 24 90 01 01 89 54 24 90 01 01 8b 44 24 90 01 02 44 24 90 01 01 8b 44 24 90 01 02 44 24 90 01 01 8b 7c 24 90 01 01 a1 90 01 04 03 fb 3d 72 05 00 00 75 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}