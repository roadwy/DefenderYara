
rule Trojan_Win32_Smokeloader_GZF_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 40 52 51 a3 ?? ?? ?? ?? ff d0 81 c4 } //5
		$a_03_1 = {73 69 c6 05 ?? ?? ?? ?? 2e c7 05 ?? ?? ?? ?? 6d 67 33 32 c7 05 ?? ?? ?? ?? 64 6c 6c 00 a2 ?? ?? ?? ?? ff 15 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}
rule Trojan_Win32_Smokeloader_GZF_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.GZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 04 3b 89 45 ?? 8b 45 ?? c1 e8 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 33 d2 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 ?? 89 55 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 33 45 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}