
rule Trojan_Win32_Smokeloader_GJZ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GJZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 1c 10 d3 ea 8b 4d c4 8d 45 e0 89 55 e0 e8 90 01 04 8b 45 e0 33 c3 31 45 f8 89 35 90 01 04 8b 45 f4 89 45 e4 8b 45 f8 29 45 e4 8b 45 e4 89 45 f4 81 45 90 01 01 47 86 c8 61 ff 4d 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Smokeloader_GJZ_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.GJZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c7 33 c1 2b f0 89 44 24 90 01 01 8b c6 c1 e0 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b ce c1 e9 90 01 01 8d 3c 2e c7 05 90 01 04 19 36 6b ff c7 05 90 01 08 89 4c 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}