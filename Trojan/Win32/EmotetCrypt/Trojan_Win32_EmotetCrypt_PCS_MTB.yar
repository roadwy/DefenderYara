
rule Trojan_Win32_EmotetCrypt_PCS_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PCS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c3 33 d2 8b 5d ?? 0f b6 0c 33 03 c1 b9 ?? ?? ?? ?? f7 f1 8b 4d ?? 0f b6 04 32 8b 55 ?? 32 04 0a 88 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}