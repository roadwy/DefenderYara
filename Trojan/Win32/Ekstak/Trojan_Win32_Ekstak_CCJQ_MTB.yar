
rule Trojan_Win32_Ekstak_CCJQ_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.CCJQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a c2 32 c1 8b 0d ?? ?? ?? ?? 24 ?? 68 ?? ?? ?? ?? a2 ?? ?? ?? ?? 8b c6 d1 e8 03 c8 33 c0 89 0d ?? ?? ?? ?? 83 e1 07 8a c2 57 0f af c8 03 f1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}