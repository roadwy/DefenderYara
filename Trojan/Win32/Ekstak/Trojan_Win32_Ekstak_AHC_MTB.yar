
rule Trojan_Win32_Ekstak_AHC_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 20 53 56 57 a1 ?? ?? ?? 00 c1 e0 03 0b 05 ?? ?? ?? 00 89 45 ec c7 45 f0 00 00 00 00 df 6d ec dd 1d ?? ?? ?? 00 8b 0d ?? ?? ?? 00 33 0d ?? ?? ?? 00 d1 e1 81 f9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}