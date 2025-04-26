
rule Trojan_Win32_Glupteba_AS_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.AS!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b c1 8b d8 33 d2 8b c6 f7 f3 8b 45 0c 8b 5d 08 8d 0c 3e 8a 14 02 32 14 0b 46 88 11 } //10
		$a_01_1 = {66 b8 b8 1a 66 bb bb 06 66 b9 b9 00 66 ba ba 01 66 be be ff 66 bf bf 32 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}