
rule Trojan_Win32_Igoogloader_RB_MTB{
	meta:
		description = "Trojan:Win32/Igoogloader.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f bf 45 b4 b9 67 cb ff ff 2b c8 03 4d f0 8b 85 6c ff ff ff f7 d9 1b c9 41 89 0d ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 2b c8 03 8d 6c ff ff ff 4a 89 8d 6c ff ff ff 66 8b 45 e4 fe 05 ?? ?? ?? ?? b1 b3 f6 e9 88 45 f8 85 d2 7f b7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}