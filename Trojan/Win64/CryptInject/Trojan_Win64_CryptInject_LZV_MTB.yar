
rule Trojan_Win64_CryptInject_LZV_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.LZV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {4d 89 e2 8b 55 c3 4c 89 55 e5 05 eb 14 00 00 48 03 45 c3 4c 8b 45 f9 48 01 4d b5 32 45 dc 4c 8b 65 c9 4c 01 d8 03 45 d6 48 c7 c0 ?? ?? ?? ?? 88 f2 89 45 e4 48 ff 04 24 b9 06 00 00 00 3b 0c 24 0f 8c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}