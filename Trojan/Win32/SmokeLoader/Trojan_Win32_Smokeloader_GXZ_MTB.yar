
rule Trojan_Win32_Smokeloader_GXZ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {30 04 33 83 ff 0f 75 90 01 01 ff 15 90 01 04 46 3b f7 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Smokeloader_GXZ_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {30 14 30 83 ff 0f 90 01 02 6a 00 6a 00 53 8d 44 24 90 01 01 50 55 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Smokeloader_GXZ_MTB_3{
	meta:
		description = "Trojan:Win32/Smokeloader.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {72 00 6e 00 c7 05 90 01 04 65 00 6c 00 c7 05 90 01 04 33 00 32 00 c7 05 90 01 04 2e 00 64 00 c7 05 90 01 04 6c 00 6c 00 c7 05 90 01 04 6b 00 65 00 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Smokeloader_GXZ_MTB_4{
	meta:
		description = "Trojan:Win32/Smokeloader.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {72 00 6e 00 c7 05 90 01 04 65 00 6c 00 c7 05 90 01 04 33 00 32 00 c7 05 90 01 04 2e 00 64 00 c7 05 90 01 04 6c 00 6c 00 66 89 0d 90 01 04 c7 05 90 01 04 6b 00 65 00 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}