
rule Trojan_Win64_CryptInject_WZS_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.WZS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 d3 03 44 94 50 41 81 e0 96 03 00 00 99 41 f7 fb 48 63 d2 8b 44 94 50 44 89 e2 41 32 44 15 00 48 8b 94 24 ?? ?? ?? ?? 42 88 04 12 48 8b 05 ?? ?? ?? ?? 48 8b 00 66 83 f9 1e 77 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}