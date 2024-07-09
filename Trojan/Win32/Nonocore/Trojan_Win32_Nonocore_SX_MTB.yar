
rule Trojan_Win32_Nonocore_SX_MTB{
	meta:
		description = "Trojan:Win32/Nonocore.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {59 f7 f9 0f af 45 ?? 89 45 ?? 0f b6 45 ?? 33 45 ?? 88 45 ?? 8b 45 ?? 03 45 ?? 8b 4d ?? 83 c1 ?? 0f af 4d ?? 03 c1 8b 4d ?? 03 4d ?? c1 e1 ?? 2b c1 03 45 ?? 89 45 ?? 8d 85 ?? ?? ?? ?? 85 c0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}