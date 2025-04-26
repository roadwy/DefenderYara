
rule Trojan_Win32_SmokeLoader_GCG_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GCG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 ?? 89 45 08 8d 45 08 50 c7 05 ?? ?? ?? ?? 19 36 6b ff e8 ?? ?? ?? ?? 8b 4d ?? 8b c6 c1 e0 ?? 03 45 e8 03 ce 33 c1 33 45 08 2b f8 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 74 ?? 81 45 ?? 47 86 c8 61 ff 4d f8 0f 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}