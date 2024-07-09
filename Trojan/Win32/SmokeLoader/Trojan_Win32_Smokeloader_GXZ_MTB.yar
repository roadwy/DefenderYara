
rule Trojan_Win32_Smokeloader_GXZ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 04 33 83 ff 0f 75 ?? ff 15 ?? ?? ?? ?? 46 3b f7 7c } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Smokeloader_GXZ_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 14 30 83 ff 0f ?? ?? 6a 00 6a 00 53 8d 44 24 ?? 50 55 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Smokeloader_GXZ_MTB_3{
	meta:
		description = "Trojan:Win32/Smokeloader.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 00 6e 00 c7 05 ?? ?? ?? ?? 65 00 6c 00 c7 05 ?? ?? ?? ?? 33 00 32 00 c7 05 ?? ?? ?? ?? 2e 00 64 00 c7 05 ?? ?? ?? ?? 6c 00 6c 00 c7 05 ?? ?? ?? ?? 6b 00 65 00 ff 15 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Smokeloader_GXZ_MTB_4{
	meta:
		description = "Trojan:Win32/Smokeloader.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 00 6e 00 c7 05 ?? ?? ?? ?? 65 00 6c 00 c7 05 ?? ?? ?? ?? 33 00 32 00 c7 05 ?? ?? ?? ?? 2e 00 64 00 c7 05 ?? ?? ?? ?? 6c 00 6c 00 66 89 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 6b 00 65 00 ff 15 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}