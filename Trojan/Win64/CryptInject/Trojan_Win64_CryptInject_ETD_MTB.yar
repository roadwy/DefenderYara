
rule Trojan_Win64_CryptInject_ETD_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.ETD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 83 c1 06 48 63 c8 48 8b c7 48 f7 e1 48 c1 ea 03 48 6b c2 ?? 48 2b c8 49 0f af ca 0f b6 44 0c ?? 42 32 44 03 ff 41 88 40 ff 49 ff cb 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}