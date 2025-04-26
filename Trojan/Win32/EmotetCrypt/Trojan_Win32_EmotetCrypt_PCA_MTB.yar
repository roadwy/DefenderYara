
rule Trojan_Win32_EmotetCrypt_PCA_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 37 8b da 8a 04 33 88 0c 33 88 04 37 0f b6 14 33 0f b6 c0 03 c2 33 d2 f7 35 ?? ?? ?? ?? 89 54 24 1c ff 15 ?? ?? ?? ?? 8b 44 24 10 8a 0c 28 8b 54 24 14 32 0c 32 8b 44 24 20 88 4d 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}