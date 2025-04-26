
rule Trojan_Win32_SmokeLoader_P_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.P!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 44 24 30 89 7c 24 18 8b 44 24 30 01 44 24 18 8b 44 24 10 33 44 24 18 89 44 24 18 8b 4c 24 18 89 4c 24 18 8b 44 24 18 29 44 24 14 8b 4c 24 14 8b c1 c1 e0 04 03 44 24 2c 81 3d ?? ?? ?? ?? be 01 00 00 89 44 24 10 8d 34 29 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}