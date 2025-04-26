
rule Trojan_Win64_CryptInject_LKZ_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.LKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 f3 49 0f af db 48 c1 eb ?? 44 8d 34 db 43 8d 2c 76 01 db 01 eb 41 89 f6 41 29 de 42 0f b6 1c 32 32 1c 37 88 1c 31 ff c6 83 fe 0a 4c 89 c7 48 0f 44 f8 e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}