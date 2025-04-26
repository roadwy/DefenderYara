
rule Trojan_Win32_SmokeLoader_TON_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.TON!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c2 89 45 ?? 8b c2 d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 4d ?? 8b c2 } //1
		$a_03_1 = {d3 e8 89 35 ?? ?? ?? ?? 03 45 ?? 89 45 fc 33 45 ?? 31 45 ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 29 45 ?? ff 4d ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}