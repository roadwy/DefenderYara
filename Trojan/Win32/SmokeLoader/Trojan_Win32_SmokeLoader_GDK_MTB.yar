
rule Trojan_Win32_SmokeLoader_GDK_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 33 45 ?? 83 25 ?? ?? ?? ?? ?? 31 45 ?? 2b 5d ?? 81 45 ?? 47 86 c8 61 ff 4d ?? 89 5d ?? 0f 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}