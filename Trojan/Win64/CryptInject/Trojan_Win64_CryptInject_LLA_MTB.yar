
rule Trojan_Win64_CryptInject_LLA_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.LLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 48 89 5c 24 50 48 89 6c 24 58 48 8b 48 18 48 89 74 24 60 48 89 7c 24 40 48 8b 69 10 33 ff 48 8b 45 30 48 85 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}