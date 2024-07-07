
rule Trojan_Win64_CryptInject_DC_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 f7 ef 48 03 cb 49 03 cc 41 03 d7 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 42 8a b4 29 90 01 04 03 d0 6b c2 90 01 01 41 8b cf 2b c8 48 63 c1 48 8b cf 42 32 b4 28 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}