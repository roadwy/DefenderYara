
rule Trojan_Win32_SmokeLoader_FIZ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.FIZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 4d ?? 8b c6 c1 e0 ?? 03 45 ?? 03 ce 33 c1 33 45 ?? 68 ?? ?? ?? ?? 2b f8 8d 45 ?? 50 e8 ?? ?? ?? ?? 4a 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}