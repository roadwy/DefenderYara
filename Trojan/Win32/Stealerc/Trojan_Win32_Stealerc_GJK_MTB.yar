
rule Trojan_Win32_Stealerc_GJK_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.GJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 11 83 f0 0d 8b 8d ?? ?? ?? ?? c1 e1 00 8d 95 ?? ?? ?? ?? 88 04 11 8b 85 ?? ?? ?? ?? c1 e0 00 8d 8d ?? ?? ?? ?? 0f b6 14 08 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}