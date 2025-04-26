
rule Trojan_Win32_CryptInject_MUC_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.MUC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 01 89 85 ?? ?? ff ff 8b 8d ?? ?? ff ff 3b 8d 08 f5 ff ff 73 50 8b 95 ?? ?? ff ff 03 95 ?? ?? ff ff 8b 85 b4 e3 ff ff 03 85 b8 f9 ff ff 8a 08 88 0a 56 81 ce d0 2d 00 00 81 e6 08 5e 00 00 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}