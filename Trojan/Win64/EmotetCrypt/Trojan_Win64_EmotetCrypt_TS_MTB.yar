
rule Trojan_Win64_EmotetCrypt_TS_MTB{
	meta:
		description = "Trojan:Win64/EmotetCrypt.TS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 04 50 89 84 24 dc 0c ?? ?? 8b 84 24 50 0c ?? ?? 99 83 e2 ?? 03 c2 83 e0 ?? 2b c2 48 98 48 8b 0d ?? ?? ?? ?? 0f b6 04 01 8b 8c 24 dc 0c ?? ?? 33 c8 8b c1 } //30
	condition:
		((#a_03_0  & 1)*30) >=30
 
}