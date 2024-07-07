
rule Trojan_Win32_CryptInject_PG_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 c3 71 68 00 00 8b f9 43 ff 71 00 46 8b f3 03 f8 8b fa 5b 8b f9 81 c6 90 01 04 81 f3 da 00 00 00 81 c7 90 01 04 03 f9 be 90 01 04 53 be 90 01 02 00 00 8b f0 4e 47 4f 8f 40 00 03 d9 81 eb 90 01 02 00 00 81 c7 90 01 02 00 00 41 4e 8b f1 46 8b f3 40 81 eb 90 01 04 4e 43 03 f8 8b f1 e9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}