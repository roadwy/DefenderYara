
rule Trojan_Win32_Amadey_KAB_MTB{
	meta:
		description = "Trojan:Win32/Amadey.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b c8 0f b6 46 ?? c1 e1 06 0f b6 80 ?? ?? ?? ?? 0b c8 0f b6 46 ?? c1 e1 06 83 c6 04 0f b6 80 ?? ?? ?? ?? 0b c8 8b c2 42 89 54 24 ?? 8b d1 c1 ea ?? 88 10 8b 54 24 ?? 8b c2 42 89 54 24 ?? 8b d1 c1 ea 08 88 10 8b 54 24 ?? 8b c2 42 88 08 83 ef } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}