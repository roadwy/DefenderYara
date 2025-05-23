
rule Trojan_Win32_Ursnif_BE_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_02_0 = {2b c2 0f b7 0d ?? ?? ?? ?? 2b c8 66 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 ?? 8b 0d ?? ?? ?? ?? 89 88 ?? ?? ?? ?? 0f b7 15 ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 2b d0 0f b7 0d ?? ?? ?? ?? 03 d1 } //2
		$a_02_1 = {03 ca 88 0d ?? ?? ?? ?? e9 } //1
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*1) >=3
 
}
rule Trojan_Win32_Ursnif_BE_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 c0 2b f0 8d 47 b5 83 c6 4a 0f af 35 ?? ?? ?? ?? 2b f1 0f b7 c9 03 c1 0f b7 c0 83 c0 07 03 c6 8d 7e 51 69 d0 89 1c 00 00 8d 81 04 d0 ff ff 2b d6 03 c2 0f b7 c8 0f af ca 8d 04 32 03 c0 2b cf 2b c1 05 5c 96 ff ff 05 cc cb ff ff 03 c2 8d 34 47 0f b6 05 ?? ?? ?? ?? 03 f1 0f b7 d6 81 ea 55 70 00 00 0f b7 de } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}