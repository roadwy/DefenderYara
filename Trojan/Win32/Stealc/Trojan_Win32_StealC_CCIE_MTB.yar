
rule Trojan_Win32_StealC_CCIE_MTB{
	meta:
		description = "Trojan:Win32/StealC.CCIE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 81 c2 ?? ?? ?? ?? 33 45 ?? 8b 4d ?? 33 c8 89 55 ?? 2b f9 89 4d ?? 8b 4d ?? 89 7d ?? 4e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}