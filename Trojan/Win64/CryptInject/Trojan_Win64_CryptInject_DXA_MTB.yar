
rule Trojan_Win64_CryptInject_DXA_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.DXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 03 cc 48 f7 e1 48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 1c 48 2b c8 8a 44 0c ?? 43 32 ?? ?? 41 88 02 4d 03 d4 44 3b ce 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}