
rule Trojan_Win32_DelfInject_DA_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 55 f0 2b d1 89 55 f0 0f b6 05 90 01 04 8b 4d f0 2b c8 89 4d f0 0f b6 15 90 01 04 03 55 f0 89 55 f0 0f b6 05 90 01 04 33 45 f0 89 45 f0 0f b6 0d 90 01 04 8b 55 f0 2b d1 89 55 f0 0f b6 05 90 01 04 03 45 f0 89 45 f0 8b 0d 90 01 04 03 4d ec 8a 55 f0 88 11 e9 90 00 } //0a 00 
		$a_03_1 = {8b 45 f0 2b c2 89 45 f0 b9 90 01 04 e8 90 01 04 0f b6 0d 90 01 04 03 4d f0 89 4d f0 68 90 01 04 8d 4d dc e8 90 01 04 8d 4d dc e8 90 01 04 0f b6 15 90 01 04 8b 45 f0 2b c2 89 45 f0 8b 0d 90 01 04 03 4d ec 8a 55 f0 88 11 e9 90 00 } //01 00 
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_01_3 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00  DllUnregisterServer
	condition:
		any of ($a_*)
 
}