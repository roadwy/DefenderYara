
rule Trojan_Win32_Fakerean_PA_MTB{
	meta:
		description = "Trojan:Win32/Fakerean.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 02 00 "
		
	strings :
		$a_02_0 = {89 cb 8d 3d 90 01 04 8b 00 8d 1d 90 01 04 f7 df 81 f2 90 01 04 f7 d6 35 90 01 04 50 f7 d2 87 f2 e9 90 00 } //02 00 
		$a_02_1 = {8b 45 f8 f7 da 8d 35 90 01 04 33 f8 bf 90 01 04 c1 c9 90 01 01 8f 00 8d 15 90 01 04 81 e1 90 01 04 83 c0 04 81 e1 90 01 04 f7 d3 33 f2 33 cf 89 f1 e9 90 00 } //02 00 
		$a_02_2 = {89 45 f8 f7 d6 81 d7 90 01 04 8b d3 ff 4d f4 0f 85 90 01 04 e9 90 00 } //01 00 
		$a_00_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00  VirtualProtect
	condition:
		any of ($a_*)
 
}