
rule Trojan_Win64_CryptInject_UZY_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.UZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 d0 48 8b 45 10 48 01 d0 0f b6 10 8b 45 fc 48 63 c8 48 8b 45 10 48 01 c8 83 f2 4d 88 10 83 45 fc 01 8b 45 fc 83 f8 0b 76 d2 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}