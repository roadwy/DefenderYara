
rule Trojan_Win32_SmokeLoader_SA_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 8b 4d ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 33 c3 31 45 ?? 89 35 ?? ?? ?? ?? 8b 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}