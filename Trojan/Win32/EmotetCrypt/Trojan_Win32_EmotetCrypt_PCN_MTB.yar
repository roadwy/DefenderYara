
rule Trojan_Win32_EmotetCrypt_PCN_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PCN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 14 29 0f b6 04 0f 03 c2 33 d2 f7 f6 8a 04 0a 8b 54 24 18 32 04 1a 43 88 43 ff } //1
		$a_03_1 = {0f b6 04 33 03 c2 33 d2 f7 35 90 01 04 89 54 24 20 ff 15 90 01 04 8b 44 24 14 8a 0c 28 8b 54 24 20 32 0c 32 8b 44 24 10 88 4d 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}