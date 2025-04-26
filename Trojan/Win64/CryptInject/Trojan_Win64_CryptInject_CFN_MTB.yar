
rule Trojan_Win64_CryptInject_CFN_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.CFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 63 c8 48 8b c3 48 f7 e1 48 c1 ea 02 48 6b c2 16 48 2b c8 49 0f af cf 0f b6 44 0d 8f 43 32 44 31 fc 41 88 41 ff 49 ff cc } //1
		$a_01_1 = {49 63 c8 48 8b c7 41 ff c0 48 f7 e1 48 c1 ea 04 48 6b c2 1b 48 2b c8 49 0f af cf 8a 44 0d a7 43 32 04 0a 41 88 01 49 ff c1 41 81 f8 00 ba 01 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}