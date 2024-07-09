
rule Trojan_Win64_EmotetCrypt_PS_MTB{
	meta:
		description = "Trojan:Win64/EmotetCrypt.PS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cb 4d 8d 40 01 f7 eb c1 fa ?? ff c3 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 8b 05 ?? ?? ?? ?? 48 63 d1 0f b6 0c 02 43 32 4c 01 ff 41 88 48 ff 48 ff cf } //30
	condition:
		((#a_03_0  & 1)*30) >=30
 
}