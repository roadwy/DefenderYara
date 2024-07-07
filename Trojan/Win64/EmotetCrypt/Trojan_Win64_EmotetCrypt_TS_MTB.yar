
rule Trojan_Win64_EmotetCrypt_TS_MTB{
	meta:
		description = "Trojan:Win64/EmotetCrypt.TS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 04 50 89 84 24 dc 0c 90 01 02 8b 84 24 50 0c 90 01 02 99 83 e2 90 01 01 03 c2 83 e0 90 01 01 2b c2 48 98 48 8b 0d 90 01 04 0f b6 04 01 8b 8c 24 dc 0c 90 01 02 33 c8 8b c1 90 00 } //30
	condition:
		((#a_03_0  & 1)*30) >=30
 
}