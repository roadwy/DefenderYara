
rule Trojan_Win32_Smokeloader_CZ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 8a 4d ?? 03 c3 30 08 83 7d ?? 0f 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Smokeloader_CZ_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 d3 e8 8b 4d ?? 89 45 ?? 8d 45 fc e8 ?? ?? ?? ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 89 3d ?? ?? ?? ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 29 45 ?? 8b 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Smokeloader_CZ_MTB_3{
	meta:
		description = "Trojan:Win32/Smokeloader.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 8b 4c 24 34 8d 44 24 28 c7 05 [0-04] ee 3d ea f4 89 54 24 28 e8 [0-04] 8b 44 24 20 31 44 24 10 81 3d [0-04] e6 09 00 00 75 08 56 56 ff 15 [0-04] 8b 44 24 10 31 44 24 28 8b 44 24 28 83 44 24 18 64 29 44 24 18 83 6c 24 18 64 83 3d [0-04] 0c 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}