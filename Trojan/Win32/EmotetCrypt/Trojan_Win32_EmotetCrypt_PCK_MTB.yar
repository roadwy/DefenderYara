
rule Trojan_Win32_EmotetCrypt_PCK_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PCK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 32 33 d2 0f b6 c9 03 c1 b9 90 01 04 f7 f1 8b 4d 18 2b 15 90 01 04 03 d7 8a 04 32 8b 55 f8 02 c2 8b 55 08 32 04 0a 88 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}