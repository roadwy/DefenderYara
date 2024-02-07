
rule Trojan_Win32_SmokeLoader_GTZ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GTZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b d7 d3 e2 8b 4d ec 89 45 f0 8b c7 03 55 d8 d3 e8 89 45 f8 8b 45 d4 01 45 f8 8b 45 f8 33 45 f0 89 35 90 01 04 33 d0 29 55 e4 8b 45 cc 29 45 f4 ff 4d e0 0f 85 90 00 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00  VirtualProtect
	condition:
		any of ($a_*)
 
}