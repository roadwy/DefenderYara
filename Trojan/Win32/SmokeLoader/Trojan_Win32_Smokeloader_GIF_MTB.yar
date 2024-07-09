
rule Trojan_Win32_Smokeloader_GIF_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GIF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 64 89 45 c4 83 6d ?? 64 8b 45 bc 8a 4d ?? 03 c7 30 08 83 fb 0f 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Smokeloader_GIF_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.GIF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 ?? c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8d 0c 2f 31 4c 24 ?? 8b 44 24 ?? 31 44 24 ?? 2b 74 24 ?? 81 3d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}