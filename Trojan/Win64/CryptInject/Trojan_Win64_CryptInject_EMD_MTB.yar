
rule Trojan_Win64_CryptInject_EMD_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.EMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 c2 01 c2 89 45 8e 4c 01 d8 31 8d ?? ?? ?? ?? 8b 95 7b fd ff ff 48 01 ca 2b 8d a3 fd ff ff 2b 85 ?? ?? ?? ?? 0f b7 ca 09 d0 0f b6 d6 89 d0 8a b5 ?? ?? ?? ?? 48 29 8d cc fe ff ff 31 95 b4 fe ff ff 0f b6 95 ?? ?? ?? ?? 48 ff 04 24 48 81 3c 24 ac 24 00 00 0f 8e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}