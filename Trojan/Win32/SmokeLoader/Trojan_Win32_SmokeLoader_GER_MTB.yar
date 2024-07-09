
rule Trojan_Win32_SmokeLoader_GER_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 ?? 03 c3 50 89 45 ?? 8d 45 ?? 03 ce 31 4d ?? 50 c7 05 ?? ?? ?? ?? 19 36 6b ff e8 ?? ?? ?? ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 29 45 ?? ff 4d ?? 8b 45 ?? 0f 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}