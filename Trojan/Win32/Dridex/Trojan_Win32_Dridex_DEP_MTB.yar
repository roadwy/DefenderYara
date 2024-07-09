
rule Trojan_Win32_Dridex_DEP_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DEP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 7c 24 10 2b c6 8b 0d ?? ?? ?? ?? 83 44 24 10 04 81 c1 ?? ?? ?? ?? 89 44 24 14 03 c1 8b 0f a3 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 2b c2 89 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}