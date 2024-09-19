
rule Trojan_Win64_GoLoader_EC_MTB{
	meta:
		description = "Trojan:Win64/GoLoader.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 ba 00 00 1a 3d eb 03 b2 a1 48 8d 04 0a e8 45 d0 fe ff b8 40 42 0f 00 e8 7b d1 fe ff 44 0f 11 bc 24 b8 01 00 00 e8 0d b4 f4 ff } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}