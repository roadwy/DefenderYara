
rule Trojan_Win64_CryptInject_YAP_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.YAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 01 c2 8b 85 90 01 04 48 98 48 29 c2 8b 85 90 01 04 48 98 48 01 d0 0f b6 84 05 90 01 04 44 31 c8 41 88 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}