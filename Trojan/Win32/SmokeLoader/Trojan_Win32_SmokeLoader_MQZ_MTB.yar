
rule Trojan_Win32_SmokeLoader_MQZ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.MQZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e8 03 c5 89 44 24 ?? 33 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8d 44 24 ?? e8 ?? ?? ?? ?? 83 ef ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}