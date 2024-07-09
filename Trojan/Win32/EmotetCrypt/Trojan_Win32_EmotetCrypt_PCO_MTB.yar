
rule Trojan_Win32_EmotetCrypt_PCO_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PCO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 54 24 20 8a 0c 32 8b 44 24 10 02 4c 24 30 8b 54 24 24 32 0c 02 83 c0 01 83 6c 24 18 01 88 48 ff 89 44 24 10 0f 85 } //1
		$a_03_1 = {0f b6 14 0f 0f b6 c0 03 c2 33 d2 f7 f6 8b 74 24 ?? 83 c6 01 89 74 24 ?? 03 54 24 ?? 0f b6 04 0a 8b 54 24 ?? 02 c3 32 44 32 ff 83 6c 24 ?? 01 88 46 ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}