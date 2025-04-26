
rule Trojan_Win64_CryptInject_MC{
	meta:
		description = "Trojan:Win64/CryptInject.MC,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 8c 24 18 01 00 00 48 8b 84 24 c8 00 00 00 44 0f b6 04 08 48 63 84 24 18 01 00 00 33 d2 b9 43 00 00 00 48 f7 f1 0f b6 44 14 50 41 8b d0 33 d0 48 63 8c 24 18 01 00 00 48 8b 84 24 00 01 00 00 88 14 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}