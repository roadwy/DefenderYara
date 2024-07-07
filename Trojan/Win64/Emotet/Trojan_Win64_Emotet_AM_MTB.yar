
rule Trojan_Win64_Emotet_AM_MTB{
	meta:
		description = "Trojan:Win64/Emotet.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 32 4c 32 fd 83 c5 03 88 4e fd 41 8d 48 ff f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 c2 48 98 48 8d 0c 40 } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}
rule Trojan_Win64_Emotet_AM_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d0 8b c3 ff c3 6b d2 90 01 01 2b c2 48 63 c8 42 8a 04 19 43 32 04 01 41 88 00 49 ff c0 48 83 ef 01 74 09 90 00 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}
rule Trojan_Win64_Emotet_AM_MTB_3{
	meta:
		description = "Trojan:Win64/Emotet.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 84 24 f0 0b 00 00 99 b9 90 01 01 00 00 00 f7 f9 8b c2 48 98 48 8b 0d 90 01 04 0f b6 04 01 8b 8c 24 fc 0b 00 00 33 c8 8b c1 90 00 } //6
	condition:
		((#a_03_0  & 1)*6) >=6
 
}