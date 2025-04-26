
rule Trojan_Win64_CryptInject_XZ_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.XZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 8d 4c 24 3c 4c 89 e2 41 b8 20 00 00 00 ff 15 18 2d 05 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}