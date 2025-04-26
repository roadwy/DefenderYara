
rule Trojan_Win64_CryptInject_XIR_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.XIR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 31 d2 49 f7 f0 45 8a 14 11 44 30 14 0f 48 ff c1 48 89 c8 48 81 f9 02 b0 04 00 76 e3 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}