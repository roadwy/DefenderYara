
rule Trojan_Win64_EmotetCrypt_AG_MTB{
	meta:
		description = "Trojan:Win64/EmotetCrypt.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 4c 24 ?? 41 8a 14 08 48 8b 4c 24 ?? 32 14 08 49 8b c3 b9 [0-50] 4c 63 df 48 c1 e0 ?? 4c 89 5c 24 ?? 48 2b c8 48 0f af cb 48 8d 04 0e 48 ff c6 4a 8d 0c b0 48 8b 44 24 ?? 48 89 74 24 ?? 88 14 01 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}