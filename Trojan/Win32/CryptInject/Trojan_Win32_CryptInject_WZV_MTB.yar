
rule Trojan_Win32_CryptInject_WZV_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.WZV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 81 e3 a0 eb 00 00 81 eb 8e 1d 01 00 81 c3 69 cb 00 00 5b 8b 8d f4 f4 ff ff 89 8d 54 e2 ff ff c7 85 ?? ?? ff ff 00 00 00 00 eb 0f 8b 95 ?? ?? ff ff 83 c2 01 89 95 60 f9 ff ff 8b 85 60 f9 ff ff 3b 85 7c f4 ff ff 73 50 8b 8d 54 e2 ff ff 03 8d ?? ?? ff ff 8b 95 50 e2 ff ff 03 95 ?? ?? ff ff 8a 02 88 01 56 81 f6 fc 07 01 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}