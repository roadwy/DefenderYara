
rule Trojan_Win64_CryptInject_CCIQ_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.CCIQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 8b 48 24 ff c0 48 03 ca 48 ff c2 46 30 14 09 41 3b 40 20 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}