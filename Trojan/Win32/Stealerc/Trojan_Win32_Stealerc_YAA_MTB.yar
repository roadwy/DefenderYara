
rule Trojan_Win32_Stealerc_YAA_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cb 8d 04 1f c1 e1 04 81 c1 ?? ?? ?? ?? 33 c8 8b c3 c1 e8 05 2d ?? ?? ?? ?? 33 c8 2b f1 8b ce c1 e1 04 81 e9 ?? ?? ?? ?? 8d 04 37 33 c8 8d bf ?? ?? ?? ?? 8b c6 c1 e8 05 2d ?? ?? ?? ?? 33 c8 2b d9 83 ed 01 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}