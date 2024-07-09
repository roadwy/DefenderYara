
rule Trojan_Win32_Smokeloader_GNA_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d7 d3 ea 8d 04 3b 89 45 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 ?? 8b 45 ?? 31 45 ?? 33 55 ?? 89 55 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Smokeloader_GNA_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.GNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 04 33 d3 ee 89 45 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 03 75 ?? 8b 45 ?? 31 45 ?? 33 75 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 75 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Smokeloader_GNA_MTB_3{
	meta:
		description = "Trojan:Win32/Smokeloader.GNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d6 d3 ee 8b cd 8d 44 24 ?? 89 54 24 ?? 89 74 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 81 3d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Smokeloader_GNA_MTB_4{
	meta:
		description = "Trojan:Win32/Smokeloader.GNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {62 d4 ec 26 b8 ?? ?? ?? ?? f7 64 24 ?? 8b 44 24 ?? 81 6c 24 ?? 46 47 2e 63 81 44 24 ?? d0 50 3e 7e 81 6c 24 ?? 74 f6 20 40 81 44 24 ?? 6d 8d f3 1b 81 44 24 ?? 1a 8d 4c 3c 81 6c 24 ?? a7 1e 7a 2c } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}