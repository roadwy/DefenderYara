
rule Trojan_Win32_Smokeloader_GD_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 20 89 44 24 28 8b 44 24 18 c1 e8 90 01 01 89 44 24 14 8b 44 24 3c 01 44 24 14 8b 4c 24 14 33 4c 24 28 8b 44 24 10 81 44 24 90 01 01 47 86 c8 61 33 c1 2b f0 83 eb 01 89 44 24 10 89 3d 90 01 04 89 74 24 30 0f 85 90 00 } //10
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}