
rule Trojan_Win64_CryptInject_MHZ_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.MHZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 01 7d 8d 4c 89 4d ?? 8b 85 38 ff ff ff 48 8b 55 c3 31 7d de 8b 95 55 ff ff ff 81 ef 05 3f 00 00 8d 45 8c 89 bd ?? ?? ff ff 48 05 13 0e 00 00 89 0d 85 78 0a 00 8b bd 63 ff ff ff 03 bd 47 ff ff ff 21 d1 2b 95 51 ff ff ff 48 ff 04 24 b9 01 00 00 00 3b 0c 24 7c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}