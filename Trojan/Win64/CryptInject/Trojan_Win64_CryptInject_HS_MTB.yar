
rule Trojan_Win64_CryptInject_HS_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.HS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 48 8b 48 18 48 8b 51 10 48 8b 4a 30 48 85 c9 0f 84 48 01 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}