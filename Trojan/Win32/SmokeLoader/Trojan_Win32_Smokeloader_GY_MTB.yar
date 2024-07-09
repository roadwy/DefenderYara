
rule Trojan_Win32_Smokeloader_GY_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 4d 6f 6e 69 74 6f 72 49 6e 66 6f } //1 GetMonitorInfo
		$a_01_1 = {47 65 74 54 69 6d 65 5a 6f 6e 65 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 GetTimeZoneInformation
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_80_3 = {68 75 7a 65 66 75 68 61 74 6f 63 61 6c 75 } //huzefuhatocalu  1
		$a_01_4 = {63 6f 79 75 72 65 7a 61 6a 61 74 65 76 69 70 75 6c 69 72 } //1 coyurezajatevipulir
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_80_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Smokeloader_GY_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d0 d3 e2 8d 0c 07 c1 e8 ?? 89 4c 24 18 03 54 24 38 89 44 24 14 89 54 24 10 8b 44 24 3c 01 44 24 14 8b 54 24 14 33 54 24 18 8b 44 24 10 33 c2 2b f0 81 c7 47 86 c8 61 83 ed ?? 89 44 24 10 89 1d ?? ?? ?? ?? 89 74 24 2c 89 7c 24 28 0f 85 } //10
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}