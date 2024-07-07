
rule Trojan_Win64_EmotetCrypt_GG_MTB{
	meta:
		description = "Trojan:Win64/EmotetCrypt.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 04 a0 90 01 03 89 44 24 60 8b 44 24 30 99 b9 90 01 04 f7 f9 8b c2 48 98 48 8b 0d 90 01 03 00 0f b6 04 01 8b 4c 24 60 33 c8 8b c1 90 00 } //30
	condition:
		((#a_03_0  & 1)*30) >=30
 
}