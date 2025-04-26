
rule Trojan_Win64_CryptInject_MGG_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.MGG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 c8 49 8b c6 48 f7 e1 48 8b c1 48 2b c2 48 d1 e8 48 03 c2 41 83 c5 ?? 4d 8d 49 ?? 48 c1 e8 04 48 6b c0 ?? 48 2b c8 49 0f af c8 0f b6 44 0c 20 43 32 44 0c fa 41 88 41 ff 49 ff cf 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}