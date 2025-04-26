
rule Trojan_Win64_CryptInject_AWH_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.AWH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b c3 48 f7 e1 48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 ?? 48 2b c8 49 0f af ca 0f b6 44 0c ?? 42 32 44 07 ff 41 88 40 ff 49 ff cb 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}