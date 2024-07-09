
rule Trojan_Win32_Ursnif_Soka_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.Soka!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c6 0f af c1 2b c2 a2 ?? ?? ?? ?? 0f af c1 2b c2 8b f0 8b 44 24 ?? 81 c7 ?? ?? ?? ?? 89 38 8d 44 19 ?? 0f b7 c0 6a ?? 5a 2b d0 0f b6 05 ?? ?? ?? ?? 03 ca 3d ?? ?? ?? ?? 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}