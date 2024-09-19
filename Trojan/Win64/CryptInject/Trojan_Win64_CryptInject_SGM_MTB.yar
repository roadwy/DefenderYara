
rule Trojan_Win64_CryptInject_SGM_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.SGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b c6 41 ff c2 4d 8d 49 ?? 48 f7 e1 48 c1 ea 04 48 6b c2 13 48 2b c8 49 03 cb 0f b6 44 0c 20 42 32 44 0b ff 41 88 41 ff 41 81 fa 00 54 07 00 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}