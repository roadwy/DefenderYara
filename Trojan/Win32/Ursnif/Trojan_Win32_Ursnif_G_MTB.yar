
rule Trojan_Win32_Ursnif_G_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 43 01 00 00 8b 4d ?? 66 89 01 8b 55 ?? 0f b7 02 2d da 00 00 00 8b 4d ?? 66 89 01 ba 48 01 00 00 8b 45 ?? 66 89 50 02 8b 4d ?? 0f b7 51 02 81 ea da 00 00 00 8b 45 ?? 66 89 50 02 b9 4e 01 00 00 8b 55 ?? 66 89 4a 04 8b 45 ?? 0f b7 48 04 81 e9 da 00 00 00 8b 55 ?? 66 89 4a 04 b8 3f 01 00 00 8b 4d ?? 66 89 41 06 8b 55 ?? 0f b7 42 06 2d da 00 00 00 8b 4d ?? 66 89 41 06 ba 4c 01 00 00 8b 45 ?? 66 89 50 08 8b 4d ?? 0f b7 51 08 81 ea da 00 00 00 8b 45 ?? 66 89 50 08 b9 40 01 00 00 8b 55 ?? 66 89 4a 0a 8b 45 ?? 0f b7 48 0a 81 e9 da 00 00 00 8b 55 ?? 66 89 4a 0a } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}