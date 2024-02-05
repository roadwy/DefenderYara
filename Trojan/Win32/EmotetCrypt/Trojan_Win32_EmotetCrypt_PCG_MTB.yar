
rule Trojan_Win32_EmotetCrypt_PCG_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PCG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 33 0f b6 c0 03 c1 33 d2 b9 90 01 04 f7 f1 8b 44 24 14 8b 4c 24 1c 83 c0 01 89 44 24 14 0f b6 14 32 32 54 01 ff 83 6c 24 18 01 88 50 ff 90 00 } //01 00 
		$a_01_1 = {0f b6 14 0f 0f b6 c0 03 c2 33 d2 f7 f6 8a 04 0a 8b 54 24 18 32 04 1a 43 88 43 ff } //00 00 
	condition:
		any of ($a_*)
 
}