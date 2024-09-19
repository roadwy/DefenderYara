
rule Trojan_Win64_CryptInject_UZZ_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.UZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 2b c8 0f b6 44 0c 20 43 32 44 0c ?? 41 88 41 fe 41 8d 42 03 41 83 c2 06 48 63 c8 49 8b c7 48 f7 e1 48 c1 ea 04 48 6b c2 11 48 2b c8 0f b6 44 0c 20 43 32 44 0d fa 41 88 41 ff 49 ff c8 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}