
rule Trojan_Win32_Siggen_GR_MTB{
	meta:
		description = "Trojan:Win32/Siggen.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 43 18 ff ff ff ff c7 43 28 ff ff ff ff c7 43 30 ff ff ff ff c7 43 48 28 81 40 00 c7 43 4c f0 72 40 00 8d b5 56 ff ff ff 8d 85 75 ff ff ff b1 01 eb 03 } //10
		$a_01_1 = {88 45 ef 0f be 45 ef 89 45 f4 8b 45 10 31 45 f4 8b 45 f4 88 45 ef 8a 55 ef 8b 45 e4 88 10 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}