
rule Trojan_Win64_CryptInject_KOT_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.KOT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 ff c1 48 f7 e1 48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 90 01 01 48 6b c0 90 01 01 48 2b c8 49 03 cb 0f b6 44 0c 90 01 01 42 32 44 13 ff 41 88 42 ff 41 81 f9 00 c2 1b 00 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}