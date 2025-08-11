
rule Trojan_Win32_Remcos_NR_MTB{
	meta:
		description = "Trojan:Win32/Remcos.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {46 4d 41 39 33 3f 83 c4 04 58 50 53 83 c4 04 81 e8 bf ee 00 00 58 69 8d } //3
		$a_01_1 = {3a 48 3c 5e 50 51 83 c4 04 e8 0b 00 00 00 00 33 3c 3d 50 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}
rule Trojan_Win32_Remcos_NR_MTB_2{
	meta:
		description = "Trojan:Win32/Remcos.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b d0 83 f2 00 0f af 95 ?? ?? ff ff 69 8d ?? ?? ff ff f1 fe c9 98 2b d1 89 95 ?? ?? ff ff e9 ?? ?? ?? ?? c7 85 ?? ?? ff ff 01 00 00 00 } //3
		$a_03_1 = {2b d0 33 95 ?? ?? ff ff 0f af 95 ?? ?? ff ff 69 8d ?? ?? ff ff f1 fe c9 98 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}