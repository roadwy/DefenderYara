
rule Trojan_Win32_EmotetCrypt_DG_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 2a 03 c2 33 d2 89 6c 24 18 bd 90 01 04 f7 f5 8b 44 24 44 8b 6c 24 20 83 c5 01 89 6c 24 20 2b 54 24 14 2b 54 24 1c 2b d7 2b d1 03 d6 0f b6 14 02 8b 44 24 3c 30 54 28 ff 81 fd 00 34 02 00 0f 82 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}