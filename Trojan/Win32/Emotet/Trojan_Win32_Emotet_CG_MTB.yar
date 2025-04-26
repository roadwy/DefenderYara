
rule Trojan_Win32_Emotet_CG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c0 b9 02 68 00 00 2b c8 89 0d ?? ?? ?? ?? 83 c4 14 b9 01 10 00 00 2b c8 89 0d ?? ?? ?? ?? 6a 41 59 2b c8 89 0d ?? ?? ?? ?? 6a 02 59 2b c8 89 0d ?? ?? ?? ?? b9 04 80 00 00 2b c8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}