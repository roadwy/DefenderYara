
rule Trojan_Win64_CryptInject_WTD_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.WTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d1 48 c7 c1 f1 3b 00 00 4c 89 85 ?? ?? ?? ?? 03 4d d2 89 4d cf 49 81 f2 ?? ?? ?? ?? 49 81 f0 2f b5 00 00 48 8b 45 e7 4c 29 8d 2f ff ff ff 8b 05 ?? ?? ?? ?? 31 4d dd 8b 45 e2 89 d0 2b 85 ?? ?? ?? ?? 48 ff 04 24 49 c7 c1 d7 68 00 00 4c 39 0c 24 7e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}