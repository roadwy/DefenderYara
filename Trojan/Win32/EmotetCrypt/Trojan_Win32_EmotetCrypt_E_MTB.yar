
rule Trojan_Win32_EmotetCrypt_E_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d ec 8b c7 2b 05 ?? ?? ?? ?? 47 03 c8 0f b6 c3 8b 1d ?? ?? ?? ?? 8a 04 18 30 01 8b 4d f4 3b fe 7c ?? 8b 75 08 8a 45 ff 88 06 8a 45 fe 5f 88 46 01 5e 5b 8b e5 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}