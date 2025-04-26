
rule Trojan_Win64_CryptInject_REN_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.REN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 0c 24 48 8b 44 24 ?? 0f b7 04 08 66 89 44 24 ?? 8b 04 24 83 c0 01 89 04 24 0f b7 54 24 ?? 8b 44 24 04 c1 e8 08 8b 4c 24 04 c1 e1 ?? 0b c1 8b ca 03 c8 8b 44 24 04 33 c1 89 44 24 04 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}