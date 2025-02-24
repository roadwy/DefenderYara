
rule Trojan_Win64_CryptInject_OOZ_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.OOZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 c8 49 8b c0 48 f7 e1 48 c1 ea 04 48 8d 04 52 48 c1 e0 ?? 48 2b c8 49 0f af cb 0f b6 44 0d 8f 43 32 44 0e fc 41 88 41 ff 49 ff cc 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}