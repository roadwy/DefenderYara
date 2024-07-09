
rule Trojan_Win32_SmokeLoader_J_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c2 d3 e8 8d 34 17 03 45 ?? 33 c6 31 45 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_SmokeLoader_J_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 05 03 44 24 30 c7 05 ?? ?? ?? ?? 19 36 6b ff 33 c3 31 44 24 14 c7 05 ?? ?? ?? ?? ff ff ff ff 8b 44 24 14 29 44 24 18 81 c7 47 86 c8 61 4d 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}