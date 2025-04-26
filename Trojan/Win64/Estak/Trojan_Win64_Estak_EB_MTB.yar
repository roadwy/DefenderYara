
rule Trojan_Win64_Estak_EB_MTB{
	meta:
		description = "Trojan:Win64/Estak.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c8 48 0f af c0 31 d2 49 f7 f6 b8 fb ff ff ff 29 d0 81 f9 fe ff ff 7f 0f 42 c2 89 c1 83 e1 0f 8a 84 0c a0 00 00 00 88 04 1f 48 ff c7 e9 ab fe ff ff } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}