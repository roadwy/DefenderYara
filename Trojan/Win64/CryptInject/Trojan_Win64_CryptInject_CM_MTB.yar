
rule Trojan_Win64_CryptInject_CM_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {32 84 0a e8 03 00 00 48 83 c1 01 48 8b 94 24 88 00 00 00 83 e1 0f 42 88 04 3a } //1
		$a_01_1 = {c1 e9 08 01 ca 88 50 02 89 d1 0f b6 50 01 c1 e9 08 01 ca 88 50 01 c1 ea 08 00 10 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}