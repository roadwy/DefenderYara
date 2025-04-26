
rule Trojan_Win32_SmokeLoader_GCX_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GCX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 ?? 03 45 ?? 68 ?? ?? ?? ?? 33 c3 31 45 ?? 2b 75 ?? 8d 45 ?? 50 c7 05 ?? ?? ?? ?? 19 36 6b ff e8 ?? ?? ?? ?? ff 4d ?? 0f 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}