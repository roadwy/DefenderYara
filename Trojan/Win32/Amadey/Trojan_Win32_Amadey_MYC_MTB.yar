
rule Trojan_Win32_Amadey_MYC_MTB{
	meta:
		description = "Trojan:Win32/Amadey.MYC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b f3 c1 ee ?? 03 74 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? ff 15 ?? ?? ?? ?? 8b 44 24 ?? 33 c6 89 44 24 ?? 50 8b c7 e8 ?? ?? ?? ?? 81 44 24 ?? ?? ?? ?? ?? 83 6c 24 ?? ?? 8b f8 89 7c 24 ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}