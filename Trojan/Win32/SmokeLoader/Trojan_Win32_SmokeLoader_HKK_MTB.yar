
rule Trojan_Win32_SmokeLoader_HKK_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.HKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 ?? 03 c5 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 8d 44 24 ?? 89 4c 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 29 44 24 ?? 83 ef ?? 8b 4c 24 ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}