
rule Trojan_Win64_CryptInject_BCP_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.BCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c4 e3 5d 46 d8 02 48 31 d2 c4 e3 5d 46 e0 13 49 f7 f1 c4 c3 1d 46 c0 02 45 8a 14 10 66 0f 59 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}