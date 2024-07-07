
rule Trojan_Win32_Glupteba_AC_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.AC!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c9 88 4d f7 33 d2 88 55 f6 33 c0 88 45 f5 8a 4d f7 88 4d b0 8a 55 f6 88 55 ac 8a 45 f5 88 45 a8 } //10
		$a_01_1 = {b8 01 00 00 00 6b c8 06 c6 84 0d 6c ff ff ff 33 ba 01 00 00 00 c1 e2 00 c6 84 15 6c ff ff ff 65 b8 01 00 00 00 d1 e0 c6 84 05 6c ff ff ff 72 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}