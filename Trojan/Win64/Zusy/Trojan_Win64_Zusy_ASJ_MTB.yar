
rule Trojan_Win64_Zusy_ASJ_MTB{
	meta:
		description = "Trojan:Win64/Zusy.ASJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 f7 e1 48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 ?? 48 2b c8 49 0f af cf 0f b6 44 0d ?? 41 32 44 31 fc 41 88 41 ff 49 ff cc 0f } //4
		$a_01_1 = {44 8d 4b 04 ba 00 ba 01 00 33 c9 41 b8 00 30 00 00 ff 15 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}