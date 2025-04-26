
rule Trojan_Win64_CryptInject_DDA_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.DDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c8 4c 89 95 64 ff ff ff 8b 8d a2 fe ff ff ba a4 24 00 00 48 8d 4d cc 4c 8b 85 ?? fe ff ff 48 8b 85 60 fe ff ff 4c 03 4d c0 4c 33 9d 62 ff ff ff 8b 95 c0 fe ff ff 29 c9 0f b7 d0 8b 15 ?? cc 03 00 48 2b 8d 50 ff ff ff 48 ff 04 24 48 83 3c 24 0d 0f 8e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}