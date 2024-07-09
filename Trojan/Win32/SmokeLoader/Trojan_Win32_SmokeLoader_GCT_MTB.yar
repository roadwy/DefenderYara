
rule Trojan_Win32_SmokeLoader_GCT_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GCT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 14 30 8b c6 c1 e8 05 89 45 ?? 8d 45 ?? 50 e8 ?? ?? ?? ?? 52 8d 45 ?? 50 e8 ?? ?? ?? ?? 8b 45 ?? 33 45 ?? 2b f8 8b 45 ?? 29 45 ?? ff 4d ?? 0f 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}