
rule Trojan_Win32_SmokeLoader_CW_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 c1 e8 ?? 03 45 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 45 ?? 31 45 ?? 2b 75 ?? ff 4d ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_SmokeLoader_CW_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.CW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 24 01 44 24 10 8b c6 c1 e8 05 c7 05 [0-04] 19 36 6b ff c7 05 [0-04] ff ff ff ff 89 44 24 14 8b 44 24 28 01 44 24 14 8d 0c 33 31 4c 24 10 8b 44 24 14 31 44 24 10 8b 44 24 10 29 44 24 18 81 3d [0-04] 93 00 00 00 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}