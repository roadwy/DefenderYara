
rule Trojan_Win64_ShellcodeRunner_SXG_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.SXG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 b8 ff ff 0f 00 b8 81 80 80 80 41 f7 e9 41 03 d1 c1 fa 07 8b ca c1 e9 1f 03 d1 69 ca ff 00 00 00 44 2b c9 48 8b cb } //15
		$a_01_1 = {48 8d 4d 90 4c 89 7d c8 0f 11 45 90 4c 89 7d d0 0f 11 45 a0 4c 89 7d d8 0f 11 45 b0 4c 89 7d e0 4c 89 7d e8 4c 89 7d f0 } //5
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*5) >=20
 
}