
rule Trojan_Win32_SmokeLoader_GEV_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GEV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 90 01 01 03 45 90 01 01 8d 0c 37 31 4d 90 01 01 50 89 45 90 01 01 8d 45 90 01 01 50 c7 05 90 01 04 19 36 6b ff e8 90 01 04 8b 45 90 01 01 29 45 90 01 01 81 3d 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_SmokeLoader_GEV_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.GEV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {b7 b8 c4 23 c7 45 90 01 01 ec 1c c1 2a c7 45 90 01 05 c7 85 90 01 04 46 2e d2 6c c7 45 90 01 01 3d e7 ce 7f c7 45 90 01 01 97 34 4d 72 c7 45 90 01 01 28 8c 70 73 c7 45 90 01 01 a7 75 bc 74 c7 45 90 01 01 5e 40 4f 66 c7 85 90 01 04 db 81 79 6e c7 45 90 01 01 e4 bf 0e 0d c7 85 90 01 04 1b 3d 01 4c c7 85 90 01 04 37 ac b2 42 c7 85 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}