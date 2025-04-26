
rule Trojan_Win64_CryptInject_MOA_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.MOA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d0 81 ca 00 ff ff ff 03 d0 44 8b 4c 24 44 44 8b 5d 8c 48 63 ca 8a 54 8d a0 48 8b 8d ?? ?? ?? ?? 41 32 14 09 48 8b 8d e0 03 00 00 41 88 14 0b eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}