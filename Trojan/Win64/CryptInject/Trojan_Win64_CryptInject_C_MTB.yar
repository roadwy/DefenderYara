
rule Trojan_Win64_CryptInject_C_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 8b 0f 48 8d 81 ?? ?? ?? ?? ba 01 00 00 00 45 31 c0 ff d0 b8 ?? ?? ?? ?? 49 03 07 4c 89 f1 48 89 da 49 89 f8 41 89 f1 48 83 c4 20 5b 5f 5e 41 5e 41 5f 48 ff e0 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}